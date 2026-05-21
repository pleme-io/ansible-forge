//! Bundled Python helper distributed at
//! `plugins/module_utils/akeyless_client.py` in the generated collection.
//!
//! Every emitted Ansible module imports from this helper, so the only
//! Akeyless SDK touch points (auth, request shaping, error mapping)
//! live here rather than being inlined per module.

/// Source of the `akeyless_client.py` helper.
///
/// Idiomatic, ~120 `LoC`, depends on `akeyless` (the official Python SDK).
pub const AKEYLESS_CLIENT_PY: &str = r#"# -*- coding: utf-8 -*-
# Copyright: (c) 2026, pleme-io
# MIT License
#
# Auto-generated module utility for the Akeyless V2 API.
# This file ships at plugins/module_utils/akeyless_client.py.
# All generated resource modules import get_client, call_api, build_body
# from here -- it is the only place that touches the akeyless SDK directly.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import inspect
import os

try:
    import akeyless
    from akeyless.exceptions import ApiException
    HAS_AKEYLESS = True
    AKEYLESS_IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - exercised by Ansible at runtime
    HAS_AKEYLESS = False
    AKEYLESS_IMPORT_ERROR = exc

DEFAULT_GATEWAY_URL = "https://api.akeyless.io"
DEFAULT_ACCESS_TYPE = "access_key"


def _require_sdk(module):
    if not HAS_AKEYLESS:
        module.fail_json(
            msg="The 'akeyless' Python package is required. Install with 'pip install akeyless>=5.0.22'.",
            exception=str(AKEYLESS_IMPORT_ERROR),
        )


def get_client(module):
    """Return (V2Api client, access token) for the module's auth params.

    Resolves gateway/credentials from (in priority order):
      1. module.params['gateway_url' | 'access_id' | 'access_key' | 'access_type']
      2. AKEYLESS_GATEWAY_URL / AKEYLESS_ACCESS_ID / AKEYLESS_ACCESS_KEY env vars
      3. AKEYLESS_TOKEN env var (used directly as token; no auth call performed)
    """
    _require_sdk(module)

    params = module.params or {}
    gateway_url = params.get("gateway_url") or os.environ.get("AKEYLESS_GATEWAY_URL") or DEFAULT_GATEWAY_URL
    access_id = params.get("access_id") or os.environ.get("AKEYLESS_ACCESS_ID")
    access_key = params.get("access_key") or os.environ.get("AKEYLESS_ACCESS_KEY")
    access_type = params.get("access_type") or DEFAULT_ACCESS_TYPE

    configuration = akeyless.Configuration(host=gateway_url)
    client = akeyless.V2Api(akeyless.ApiClient(configuration))

    pre_issued = os.environ.get("AKEYLESS_TOKEN")
    if pre_issued:
        return client, pre_issued

    if not access_id:
        module.fail_json(msg="access_id is required (set module param or AKEYLESS_ACCESS_ID env)")

    auth_body = akeyless.Auth(access_id=access_id, access_key=access_key, access_type=access_type)
    try:
        auth_res = client.auth(auth_body)
    except ApiException as exc:
        module.fail_json(msg="Akeyless auth failed: %s" % (exc.body or exc.reason), status=getattr(exc, "status", None))
    token = getattr(auth_res, "token", None)
    if not token:
        module.fail_json(msg="Akeyless auth returned no token")
    return client, token


def build_body(model_class_name, params):
    """Instantiate akeyless.<model_class_name>(**filtered_params).

    Filters params to those the model accepts AND drops None values.
    """
    _ensure_sdk_loaded()
    model_cls = getattr(akeyless, model_class_name, None)
    if model_cls is None:
        raise ValueError("Unknown Akeyless model: %s" % model_class_name)
    try:
        accepted = set(inspect.signature(model_cls.__init__).parameters)
    except (TypeError, ValueError):
        accepted = set(getattr(model_cls, "attribute_map", {}).keys())
    filtered = {k: v for k, v in (params or {}).items() if v is not None and k in accepted}
    return model_cls(**filtered)


def call_api(module, client, method_name, body, swallow_404=False):
    """Invoke client.<method_name>(body) and return a dict.

    If swallow_404 is true, a 404 ApiException returns None instead of
    failing the module -- used by read_resource to detect absence.
    """
    method = getattr(client, method_name, None)
    if method is None:
        module.fail_json(msg="Akeyless V2Api has no method '%s'" % method_name)
    try:
        result = method(body)
    except ApiException as exc:
        status = getattr(exc, "status", None)
        if swallow_404 and status == 404:
            return None
        module.fail_json(
            msg="Akeyless API call %s failed: %s" % (method_name, exc.body or exc.reason),
            status=status,
        )
    return _to_dict(result)


def _to_dict(result):
    if result is None:
        return None
    if hasattr(result, "to_dict"):
        return result.to_dict()
    if isinstance(result, dict):
        return result
    return {"result": result}


def _ensure_sdk_loaded():
    if not HAS_AKEYLESS:
        raise RuntimeError("akeyless SDK not importable: %s" % AKEYLESS_IMPORT_ERROR)
"#;
