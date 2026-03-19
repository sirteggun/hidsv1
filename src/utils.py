import os
import yaml
import logging
import json
import hashlib
import re
import time
from typing import Any, Dict, Optional, Union, List, Tuple, Callable
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_PATTERN_CACHE: Dict[str, Tuple[float, float, Dict[str, Any]]] = {}
_PATTERN_CACHE_MAXSIZE = 128

def validate_regex(pattern: str) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

def _get_file_hash(filepath: str) -> str:
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception:
        return ""

def _get_file_metadata(filepath: str) -> Tuple[float, str]:
    mtime = 0.0
    try:
        mtime = os.path.getmtime(filepath)
    except OSError:
        pass
    file_hash = _get_file_hash(filepath)
    return mtime, file_hash

def _validate_pattern_dict(data: Any, filepath: str, strict: bool = True) -> List[str]:
    errors = []
    if not isinstance(data, dict):
        errors.append(f"Pattern file {filepath} must contain a dictionary, got {type(data).__name__}")
        return errors

    for key, value in data.items():
        if not isinstance(key, str):
            errors.append(f"Pattern key must be string, got {type(key).__name__}: {key}")
        if isinstance(value, str):
            if not validate_regex(value):
                errors.append(f"Invalid regex pattern for key '{key}': {value}")
        elif isinstance(value, dict):
            if "pattern" in value:
                if not isinstance(value["pattern"], str):
                    errors.append(f"Pattern for key '{key}' must have string 'pattern' field")
                elif not validate_regex(value["pattern"]):
                    errors.append(f"Invalid regex in pattern for key '{key}': {value['pattern']}")
            if "type" in value and not isinstance(value["type"], str):
                errors.append(f"Field 'type' for key '{key}' must be string")
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if not isinstance(item, str):
                    errors.append(f"Pattern list item {idx} for key '{key}' must be string, got {type(item).__name__}")
                elif not validate_regex(item):
                    errors.append(f"Invalid regex in list for key '{key}' at index {idx}: {item}")
        elif value is not None:
            errors.append(f"Pattern value for key '{key}' must be str, dict, list or None, got {type(value).__name__}")
    return errors

def _load_single_pattern_file(
    filepath: str,
    raise_on_error: bool = False,
    validate: bool = True,
    strict_validation: bool = True
) -> Tuple[Dict[str, Any], List[str]]:
    errors = []
    if not os.path.exists(filepath):
        msg = f"Pattern file not found: {filepath}"
        if raise_on_error:
            raise FileNotFoundError(msg)
        logger.warning(msg)
        return {}, [msg]

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        msg = f"YAML parsing error in {filepath}: {e}"
        if raise_on_error:
            raise ValueError(msg) from e
        logger.error(msg)
        return {}, [msg]
    except PermissionError as e:
        msg = f"Permission denied reading {filepath}: {e}"
        if raise_on_error:
            raise PermissionError(msg) from e
        logger.error(msg)
        return {}, [msg]
    except Exception as e:
        msg = f"Unexpected error reading {filepath}: {e}"
        if raise_on_error:
            raise RuntimeError(msg) from e
        logger.exception(msg)
        return {}, [msg]

    if data is None:
        data = {}

    if validate:
        errors = _validate_pattern_dict(data, filepath, strict=strict_validation)
        if errors:
            for err in errors:
                logger.error(err)
            if raise_on_error:
                raise ValueError(f"Pattern validation failed for {filepath}: {errors}")
            return {}, errors

    logger.debug(f"Patterns loaded from {filepath}: {list(data.keys())}")
    return data, errors

def _merge_patterns(
    base: Dict[str, Any],
    overlay: Dict[str, Any],
    strategy: str = "deep_merge"
) -> Dict[str, Any]:
    result = base.copy()
    for key, value in overlay.items():
        if strategy == "deep_merge":
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = _merge_patterns(result[key], value, strategy)
            else:
                result[key] = value
        elif strategy == "override":
            result[key] = value
        elif strategy == "keep_existing":
            if key not in result:
                result[key] = value
        else:
            result[key] = value
    return result

def load_patterns_from_yaml(
    filepath: Union[str, List[str]],
    raise_on_error: bool = False,
    use_cache: bool = True,
    validate: bool = True,
    strict_validation: bool = True,
    merge_strategy: str = "deep_merge",
    fallback: Optional[Dict[str, Any]] = None,
    parallel: bool = False,
    max_workers: int = 4
) -> Dict[str, Any]:
    if isinstance(filepath, str):
        sources = [filepath]
    else:
        sources = filepath

    if not sources:
        logger.warning("No pattern sources provided")
        return fallback or {}

    if use_cache:
        cache_key = "|".join(sorted(sources))
        cached = _PATTERN_CACHE.get(cache_key)
        if cached:
            cached_mtimes, cached_hashes, cached_data = cached
            current_meta = [_get_file_metadata(src) for src in sources]
            current_mtimes = [m for m, _ in current_meta]
            current_hashes = [h for _, h in current_meta]
            if cached_mtimes == current_mtimes and cached_hashes == current_hashes:
                logger.debug(f"Using cached patterns for {cache_key}")
                return cached_data.copy()
            else:
                logger.debug(f"Cache invalid for {cache_key}, reloading")

    all_data = []
    all_errors = []
    if parallel and len(sources) > 1:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(sources))) as executor:
            future_to_src = {executor.submit(_load_single_pattern_file, src, raise_on_error, validate, strict_validation): src for src in sources}
            for future in as_completed(future_to_src):
                src = future_to_src[future]
                try:
                    data, errors = future.result()
                    if data:
                        all_data.append(data)
                    all_errors.extend(errors)
                except Exception as e:
                    logger.error(f"Failed to load {src}: {e}")
                    if raise_on_error:
                        raise
    else:
        for src in sources:
            data, errors = _load_single_pattern_file(src, raise_on_error, validate, strict_validation)
            if data:
                all_data.append(data)
            all_errors.extend(errors)

    if all_errors and not raise_on_error:
        logger.error(f"Errors loading patterns: {all_errors}")

    if not all_data:
        if fallback is not None:
            logger.info("No patterns loaded, using fallback")
            return fallback
        return {}

    result = {}
    for data in all_data:
        result = _merge_patterns(result, data, strategy=merge_strategy)

    if use_cache and result and len(_PATTERN_CACHE) < _PATTERN_CACHE_MAXSIZE:
        meta = [_get_file_metadata(src) for src in sources]
        mtimes = [m for m, _ in meta]
        hashes = [h for _, h in meta]
        _PATTERN_CACHE[cache_key] = (mtimes, hashes, result.copy())

    return result

def clear_pattern_cache() -> None:
    _PATTERN_CACHE.clear()
    logger.info("Pattern cache cleared")

def validate_patterns(patterns: Dict[str, Any], strict: bool = True) -> List[str]:
    return _validate_pattern_dict(patterns, "<runtime>", strict)

def flatten_patterns(patterns: Dict[str, Any], prefix: str = "") -> Dict[str, str]:
    flat = {}
    for key, value in patterns.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, str):
            flat[full_key] = value
        elif isinstance(value, dict):
            if "pattern" in value and isinstance(value["pattern"], str):
                flat[full_key] = value["pattern"]
            else:
                flat.update(flatten_patterns(value, full_key))
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, str):
                    flat[f"{full_key}.{idx}"] = item
    return flat

def export_patterns_to_json(filepath: str, patterns: Dict[str, Any], indent: int = 2) -> bool:
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(patterns, f, indent=indent, default=str)
        logger.info(f"Patterns exported to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Failed to export patterns to {filepath}: {e}")
        return False

def export_patterns_to_yaml(filepath: str, patterns: Dict[str, Any]) -> bool:
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(patterns, f, default_flow_style=False, allow_unicode=True)
        logger.info(f"Patterns exported to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Failed to export patterns to {filepath}: {e}")
        return False

def reload_patterns(filepath: Union[str, List[str]], **kwargs) -> Dict[str, Any]:
    return load_patterns_from_yaml(filepath, use_cache=False, **kwargs)

def save_patterns_cache(filepath: str) -> bool:
    try:
        serializable_cache = {}
        for key, (mtimes, hashes, data) in _PATTERN_CACHE.items():
            serializable_cache[key] = {
                "mtimes": mtimes,
                "hashes": hashes,
                "data": data
            }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(serializable_cache, f, default=str)
        return True
    except Exception as e:
        logger.error(f"Failed to save pattern cache: {e}")
        return False

def load_patterns_cache(filepath: str) -> bool:
    global _PATTERN_CACHE
    try:
        if not os.path.exists(filepath):
            return False
        with open(filepath, 'r', encoding='utf-8') as f:
            loaded = json.load(f)
        restored = {}
        for key, value in loaded.items():
            restored[key] = (value["mtimes"], value["hashes"], value["data"])
        _PATTERN_CACHE.update(restored)
        logger.info(f"Loaded pattern cache from {filepath} with {len(restored)} entries")
        return True
    except Exception as e:
        logger.error(f"Failed to load pattern cache: {e}")
        return False