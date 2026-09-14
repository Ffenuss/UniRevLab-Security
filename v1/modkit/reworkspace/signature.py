"""Conservative Rodroid/IL2CPP C-signature contracts used across RE and Menu Builder."""
from __future__ import annotations

import re


def rodroid_signature_contract(signature: str) -> dict:
    """Extract a UI-callable contract without treating ABI shape as intent.

    ``void Update(float)`` and ``.ctor(int)`` have the same low-level shape as a
    numeric setter, so a binding suggestion is emitted only for method-name
    patterns which are compatible with an explicit menu control.
    """
    text = str(signature or "").strip()
    return_c = text.split(None, 1)[0] if text else ""
    fn_match = re.match(r"^\s*\S+\s+([A-Za-z0-9_$]+)\s*\(", text)
    c_function = fn_match.group(1) if fn_match else ""
    method_token = c_function.rsplit("__", 1)[-1].lstrip("_") if c_function else ""
    params_text = text.rsplit("(", 1)[-1].rsplit(")", 1)[0] if "(" in text else ""
    raw_params = [p.strip() for p in params_text.split(",") if p.strip()]
    has_this = any(re.search(r"\b__this\b", p) for p in raw_params)
    user_params = [p for p in raw_params if "MethodInfo" not in p and not re.search(r"\b__this\b", p)]
    is_static = not has_this

    action_name = bool(re.match(
        r"(?i)^(toggle|activate|deactivate|enable|disable|show|hide|open|close|spawn|give|teleport|port|execute|run|apply|reset)[A-Za-z0-9_]*$",
        method_token,
    ))
    bool_setter_name = bool(re.match(
        r"(?i)^(set_|set|enable|disable|toggle|activate|deactivate|show|hide)[A-Za-z0-9_]*$",
        method_token,
    ))
    numeric_setter_name = bool(re.match(r"(?i)^(set_|set)[A-Za-z0-9_]*$", method_token))

    suggestion = None
    value_c = None
    value_kind = None
    managed_value_type = None
    suggested_control_type = None
    auto_binding_safe = False
    runtime_value_supported = True
    if return_c == "void" and len(user_params) == 0 and action_name:
        suggestion = "action"
        suggested_control_type = "button"
        auto_binding_safe = True
    elif return_c == "void" and len(user_params) == 1:
        p0 = user_params[0].casefold()
        if re.search(r"(^|\s)bool(\s|$)", p0):
            value_c, value_kind, managed_value_type = "bool", "bool", "System.Boolean"
            suggested_control_type = "toggle"
            if bool_setter_name:
                suggestion = "bool_setter"
                auto_binding_safe = True
        else:
            float_match = re.search(r"\b(double|float)\b", p0)
            int_match = re.search(r"\b(u?int(?:8|16|32|64)(?:_t)?)\b", p0)
            if float_match:
                value_c, value_kind = float_match.group(1), "float"
                managed_value_type = "System.Double" if value_c == "double" else "System.Single"
                suggested_control_type = "slider_float"
                runtime_value_supported = value_c == "float"
                if numeric_setter_name and runtime_value_supported:
                    suggestion = "number_setter"
                    auto_binding_safe = True
            elif int_match:
                value_c, value_kind = int_match.group(1), "int"
                bits = re.search(r"(8|16|32|64)", value_c)
                unsigned = value_c.startswith("u")
                managed_value_type = ("System.UInt" if unsigned else "System.Int") + (bits.group(1) if bits else "32")
                suggested_control_type = "slider_int"
                runtime_value_supported = value_c in {"int32", "int32_t"}
                if numeric_setter_name and runtime_value_supported:
                    suggestion = "number_setter"
                    auto_binding_safe = True

    resolver_suggestion = None
    if (is_static and return_c == "bool" and len(user_params) == 1 and "**" in user_params[0]
            and re.match(r"(?i)^tryget", method_token)):
        resolver_suggestion = "out_ptr_bool"
    elif (is_static and len(user_params) == 0 and return_c.endswith("*")
          and re.match(r"(?i)^(?:get_?instance|getinstance|instance)$", method_token)):
        resolver_suggestion = "return_ptr"
    blocker = None
    if value_kind in {"int", "float"} and numeric_setter_name and not runtime_value_supported:
        blocker = "generic-runtime-value-abi-unsupported"
    elif suggestion and not is_static:
        blocker = "instance-method-needs-confirmed-instance-resolver"
    return {
        "signature": text, "returnC": return_c, "cFunction": c_function, "methodToken": method_token,
        "rawParams": raw_params, "userParams": user_params, "managedParamCount": len(user_params),
        "isStatic": is_static, "hasThis": has_this,
        "bindingSuggestion": suggestion, "bindingBlocker": blocker,
        "suggestedControlType": suggested_control_type,
        "valueC": value_c, "valueKind": value_kind, "managedValueType": managed_value_type,
        "autoBindingSafe": auto_binding_safe, "runtimeValueSupported": runtime_value_supported,
        "resolverSuggestion": resolver_suggestion,
    }
