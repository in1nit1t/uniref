from uniref.define.constant import *

mono_native_func_name = [
    "g_free", "mono_free", "mono_get_root_domain", "mono_thread_attach", "mono_thread_detach",
    "mono_thread_cleanup", "mono_object_get_class", "mono_domain_foreach", "mono_domain_set",
    "mono_domain_get", "mono_assembly_foreach", "mono_assembly_get_image", "mono_image_get_assembly",
    "mono_image_get_name", "mono_image_get_filename", "mono_image_get_table_info", "mono_image_rva_map",
    "mono_table_info_get_rows", "mono_metadata_decode_row_col", "mono_metadata_string_heap", "mono_class_get",
    "mono_class_from_typeref", "mono_class_name_from_token", "mono_class_from_name_case", "mono_class_from_name",
    "mono_class_get_name", "mono_class_get_namespace", "mono_class_get_methods", "mono_class_get_method_from_name",
    "mono_class_get_fields", "mono_class_get_parent", "mono_class_get_image", "mono_class_is_generic",
    "mono_class_vtable", "mono_class_from_mono_type", "mono_class_get_element_class", "mono_class_instance_size",
    "mono_class_num_fields", "mono_class_num_methods", "mono_field_get_name", "mono_field_get_type",
    "mono_field_get_parent", "mono_field_get_offset", "mono_field_get_flags", "mono_type_get_name",
    "mono_type_get_type", "mono_type_get_name_full", "mono_method_get_name", "mono_method_get_class",
    "mono_method_get_header", "mono_method_signature", "mono_method_get_param_names", "mono_signature_get_desc",
    "mono_signature_get_params", "mono_signature_get_param_count", "mono_signature_get_return_type",
    "mono_compile_method", "mono_free_method", "mono_jit_info_table_find", "mono_jit_info_get_method",
    "mono_jit_info_get_code_start", "mono_jit_info_get_code_size", "mono_jit_exec", "mono_method_header_get_code",
    "mono_disasm_code", "mono_vtable_get_static_field_data", "mono_method_desc_new", "mono_method_desc_from_method",
    "mono_method_desc_free", "mono_string_new", "mono_string_to_utf8", "mono_array_new", "mono_value_box",
    "mono_object_unbox", "mono_object_new", "mono_class_get_type", "mono_class_get_nesting_type", "mono_image_open",
    "mono_method_desc_search_in_image", "mono_runtime_invoke", "mono_runtime_object_init", "mono_assembly_name_new",
    "mono_assembly_loaded", "mono_assembly_open", "mono_field_static_get_value", "mono_field_static_set_value",
    "mono_class_get_field_from_name", "mono_method_get_flags", "mono_type_get_class", "mono_class_get_flags"
]

il2cpp_native_func_name = [
    "g_free", "il2cpp_free", "il2cpp_get_root_domain", "il2cpp_thread_attach", "il2cpp_thread_detach",
    "il2cpp_object_get_class", "il2cpp_domain_foreach", "il2cpp_domain_set", "il2cpp_domain_get",
    "il2cpp_assembly_foreach", "il2cpp_assembly_get_image", "il2cpp_image_get_assembly", "il2cpp_image_get_name",
    "il2cpp_image_get_table_info", "il2cpp_image_rva_map", "il2cpp_table_info_get_rows",
    "il2cpp_metadata_decode_row_col", "il2cpp_metadata_string_heap", "il2cpp_class_get",
    "il2cpp_class_from_typeref", "il2cpp_class_name_from_token", "il2cpp_class_from_name_case",
    "il2cpp_class_from_name", "il2cpp_class_get_name", "il2cpp_class_get_namespace", "il2cpp_class_get_methods",
    "il2cpp_class_get_method_from_name", "il2cpp_class_get_fields", "il2cpp_class_get_parent",
    "il2cpp_class_get_image", "il2cpp_class_is_generic", "il2cpp_class_vtable", "il2cpp_class_from_mono_type",
    "il2cpp_class_get_element_class", "il2cpp_class_instance_size", "il2cpp_class_num_fields",
    "il2cpp_class_num_methods", "il2cpp_field_get_name", "il2cpp_field_get_type", "il2cpp_field_get_parent",
    "il2cpp_field_get_offset", "il2cpp_field_get_flags", "il2cpp_type_get_name", "il2cpp_type_get_type",
    "il2cpp_type_get_name_full", "il2cpp_method_get_name", "il2cpp_method_get_class", "il2cpp_method_get_header",
    "il2cpp_method_signature", "il2cpp_method_get_param_names", "il2cpp_signature_get_desc",
    "il2cpp_signature_get_params", "il2cpp_signature_get_param_count", "il2cpp_signature_get_return_type",
    "il2cpp_compile_method", "il2cpp_free_method", "il2cpp_jit_info_table_find", "il2cpp_jit_info_get_method",
    "il2cpp_jit_info_get_code_start", "il2cpp_jit_info_get_code_size", "il2cpp_jit_exec",
    "il2cpp_method_header_get_code", "il2cpp_disasm_code", "il2cpp_vtable_get_static_field_data",
    "il2cpp_method_desc_new", "il2cpp_method_desc_from_method", "il2cpp_method_desc_free", "il2cpp_string_new",
    "il2cpp_string_to_utf8", "il2cpp_array_new", "il2cpp_value_box", "il2cpp_object_unbox", "il2cpp_object_new",
    "il2cpp_class_get_type", "il2cpp_method_desc_search_in_image", "il2cpp_runtime_invoke",
    "il2cpp_runtime_object_init", "il2cpp_assembly_name_new", "il2cpp_assembly_loaded", "il2cpp_assembly_open",
    "il2cpp_image_open", "il2cpp_image_get_filename", "il2cpp_class_get_nesting_type", "il2cpp_field_static_get_value",
    "il2cpp_field_static_set_value", "il2cpp_domain_get_assemblies", "il2cpp_image_get_class_count",
    "il2cpp_image_get_class", "il2cpp_type_get_assembly_qualified_name", "il2cpp_string_chars",
    "il2cpp_method_get_param_count", "il2cpp_method_get_param_name", "il2cpp_method_get_param",
    "il2cpp_method_get_return_type", "il2cpp_class_from_type", "il2cpp_class_get_field_from_name",
    "il2cpp_method_get_flags", "il2cpp_type_get_class", "il2cpp_class_get_flags"
]

il2cpp_mono_native_func_map = {
    "g_free": "g_free",
    "il2cpp_free": "mono_free",
    "il2cpp_get_root_domain": "mono_get_root_domain",
    "il2cpp_thread_attach": "mono_thread_attach",
    "il2cpp_thread_detach": "mono_thread_detach",
    "il2cpp_object_get_class": "mono_object_get_class",
    "il2cpp_domain_foreach": "mono_domain_foreach",
    "il2cpp_domain_set": "mono_domain_set",
    "il2cpp_domain_get": "mono_domain_get",
    "il2cpp_assembly_foreach": "mono_assembly_foreach",
    "il2cpp_assembly_get_image": "mono_assembly_get_image",
    "il2cpp_image_get_assembly": "mono_image_get_assembly",
    "il2cpp_image_get_name": "mono_image_get_name",
    "il2cpp_image_get_table_info": "mono_image_get_table_info",
    "il2cpp_image_rva_map": "mono_image_rva_map",
    "il2cpp_table_info_get_rows": "mono_table_info_get_rows",
    "il2cpp_metadata_decode_row_col": "mono_metadata_decode_row_col",
    "il2cpp_metadata_string_heap": "mono_metadata_string_heap",
    "il2cpp_class_get": "mono_class_get",
    "il2cpp_class_from_typeref": "mono_class_from_typeref",
    "il2cpp_class_name_from_token": "mono_class_name_from_token",
    "il2cpp_class_from_name_case": "mono_class_from_name_case",
    "il2cpp_class_from_name": "mono_class_from_name",
    "il2cpp_class_get_name": "mono_class_get_name",
    "il2cpp_class_get_flags": "mono_class_get_flags",
    "il2cpp_class_get_namespace": "mono_class_get_namespace",
    "il2cpp_class_get_methods": "mono_class_get_methods",
    "il2cpp_class_get_method_from_name": "mono_class_get_method_from_name",
    "il2cpp_class_get_fields": "mono_class_get_fields",
    "il2cpp_class_get_parent": "mono_class_get_parent",
    "il2cpp_class_get_image": "mono_class_get_image",
    "il2cpp_class_is_generic": "mono_class_is_generic",
    "il2cpp_class_vtable": "mono_class_vtable",
    "il2cpp_class_from_mono_type": "mono_class_from_mono_type",
    "il2cpp_class_get_element_class": "mono_class_get_element_class",
    "il2cpp_class_instance_size": "mono_class_instance_size",
    "il2cpp_class_num_fields": "mono_class_num_fields",
    "il2cpp_class_num_methods": "mono_class_num_methods",
    "il2cpp_field_get_name": "mono_field_get_name",
    "il2cpp_field_get_type": "mono_field_get_type",
    "il2cpp_field_get_parent": "mono_field_get_parent",
    "il2cpp_field_get_offset": "mono_field_get_offset",
    "il2cpp_field_get_flags": "mono_field_get_flags",
    "il2cpp_type_get_name": "mono_type_get_name",
    "il2cpp_type_get_type": "mono_type_get_type",
    "il2cpp_type_get_name_full": "mono_type_get_name_full",
    "il2cpp_method_get_name": "mono_method_get_name",
    "il2cpp_method_get_class": "mono_method_get_class",
    "il2cpp_method_get_header": "mono_method_get_header",
    "il2cpp_method_signature": "mono_method_signature",
    "il2cpp_method_get_param_names": "mono_method_get_param_names",
    "il2cpp_signature_get_desc": "mono_signature_get_desc",
    "il2cpp_signature_get_params": "mono_signature_get_params",
    "il2cpp_signature_get_param_count": "mono_signature_get_param_count",
    "il2cpp_signature_get_return_type": "mono_signature_get_return_type",
    "il2cpp_compile_method": "mono_compile_method",
    "il2cpp_free_method": "mono_free_method",
    "il2cpp_jit_info_table_find": "mono_jit_info_table_find",
    "il2cpp_jit_info_get_method": "mono_jit_info_get_method",
    "il2cpp_jit_info_get_code_start": "mono_jit_info_get_code_start",
    "il2cpp_jit_info_get_code_size": "mono_jit_info_get_code_size",
    "il2cpp_jit_exec": "mono_jit_exec",
    "il2cpp_method_header_get_code": "mono_method_header_get_code",
    "il2cpp_disasm_code": "mono_disasm_code",
    "il2cpp_vtable_get_static_field_data": "mono_vtable_get_static_field_data",
    "il2cpp_method_desc_new": "mono_method_desc_new",
    "il2cpp_method_desc_from_method": "mono_method_desc_from_method",
    "il2cpp_method_desc_free": "mono_method_desc_free",
    "il2cpp_string_new": "mono_string_new",
    "il2cpp_string_to_utf8": "mono_string_to_utf8",
    "il2cpp_array_new": "mono_array_new",
    "il2cpp_value_box": "mono_value_box",
    "il2cpp_object_unbox": "mono_object_unbox",
    "il2cpp_object_new": "mono_object_new",
    "il2cpp_class_get_type": "mono_class_get_type",
    "il2cpp_class_get_nesting_type": "mono_class_get_nesting_type",
    "il2cpp_method_desc_search_in_image": "mono_method_desc_search_in_image",
    "il2cpp_runtime_invoke": "mono_runtime_invoke",
    "il2cpp_runtime_object_init": "mono_runtime_object_init",
    "il2cpp_assembly_name_new": "mono_assembly_name_new",
    "il2cpp_assembly_loaded": "mono_assembly_loaded",
    "il2cpp_assembly_open": "mono_assembly_open",
    "il2cpp_image_open": "mono_image_open",
    "il2cpp_image_get_filename": "mono_image_get_filename",
    "il2cpp_class_get_field_from_name": "mono_class_get_field_from_name",
    "il2cpp_method_get_flags": "mono_method_get_flags",
    "il2cpp_type_get_class": "mono_type_get_class",
    "il2cpp_field_static_get_value": "il2cpp_field_static_get_value",
    "il2cpp_field_static_set_value": "il2cpp_field_static_set_value",
    "il2cpp_domain_get_assemblies": "il2cpp_domain_get_assemblies",
    "il2cpp_image_get_class_count": "il2cpp_image_get_class_count",
    "il2cpp_image_get_class": "il2cpp_image_get_class",
    "il2cpp_type_get_assembly_qualified_name": "il2cpp_type_get_assembly_qualified_name",
    "il2cpp_method_get_param_count": "il2cpp_method_get_param_count",
    "il2cpp_method_get_param_name": "il2cpp_method_get_param_name",
    "il2cpp_method_get_param": "il2cpp_method_get_param",
    "il2cpp_method_get_return_type": "il2cpp_method_get_return_type",
    "il2cpp_class_from_type": "il2cpp_class_from_type",
    "il2cpp_string_chars": "il2cpp_string_chars",
}

mono_native_func_property = {
    "g_free": (1, TYPE_VOID),
    "mono_free": (1, TYPE_VOID),
    "mono_get_root_domain": (0, TYPE_VOID_P),
    "mono_thread_attach": (1, TYPE_VOID_P),
    "mono_thread_detach": (1, TYPE_VOID),
    "mono_thread_cleanup": (0, TYPE_VOID),
    "mono_object_get_class": (1, TYPE_VOID_P),
    "mono_domain_foreach": (2, TYPE_VOID),
    "mono_domain_set": (2, TYPE_INT32),
    "mono_domain_get": (0, TYPE_VOID_P),
    "mono_assembly_foreach": (2, TYPE_INT32),
    "mono_assembly_get_image": (1, TYPE_VOID_P),
    "mono_image_get_assembly": (1, TYPE_VOID_P),
    "mono_image_get_name": (1, TYPE_CHAR_P),
    "mono_image_get_filename": (1, TYPE_CHAR_P),
    "mono_image_get_table_info": (2, TYPE_VOID_P),
    "mono_image_rva_map": (2, TYPE_VOID_P),
    "mono_table_info_get_rows": (1, TYPE_INT32),
    "mono_metadata_decode_row_col": (3, TYPE_INT32),
    "mono_metadata_string_heap": (2, TYPE_CHAR_P),
    "mono_class_get": (2, TYPE_VOID_P),
    "mono_class_from_typeref": (2, TYPE_VOID_P),
    "mono_class_name_from_token": (2, TYPE_CHAR_P),
    "mono_class_from_name_case": (3, TYPE_VOID_P),
    "mono_class_from_name": (3, TYPE_VOID_P),
    "mono_class_get_name": (1, TYPE_CHAR_P),
    "mono_class_get_namespace": (1, TYPE_CHAR_P),
    "mono_class_get_methods": (2, TYPE_VOID_P),
    "mono_class_get_method_from_name": (3, TYPE_VOID_P),
    "mono_class_get_fields": (2, TYPE_VOID_P),
    "mono_class_get_parent": (1, TYPE_VOID_P),
    "mono_class_get_image": (1, TYPE_VOID_P),
    "mono_class_is_generic": (1, TYPE_INT32),
    "mono_class_vtable": (2, TYPE_VOID_P),
    "mono_class_from_mono_type": (1, TYPE_VOID_P),
    "mono_class_get_element_class": (1, TYPE_VOID_P),
    "mono_class_instance_size": (1, TYPE_INT32),
    "mono_class_num_fields": (1, TYPE_INT32),
    "mono_class_num_methods": (1, TYPE_INT32),
    "mono_field_get_name": (1, TYPE_CHAR_P),
    "mono_field_get_type": (1, TYPE_VOID_P),
    "mono_field_get_parent": (1, TYPE_VOID_P),
    "mono_field_get_offset": (1, TYPE_INT32),
    "mono_field_get_flags": (1, TYPE_INT32),
    "mono_type_get_name": (1, TYPE_CHAR_P),
    "mono_type_get_type": (1, TYPE_INT32),
    "mono_type_get_name_full": (2, TYPE_CHAR_P),
    "mono_method_get_name": (1, TYPE_CHAR_P),
    "mono_method_get_class": (1, TYPE_VOID_P),
    "mono_method_get_header": (1, TYPE_VOID_P),
    "mono_method_signature": (1, TYPE_VOID_P),
    "mono_method_get_param_names": (2, TYPE_VOID_P),
    "mono_signature_get_desc": (2, TYPE_CHAR_P),
    "mono_signature_get_params": (2, TYPE_VOID_P),
    "mono_signature_get_param_count": (1, TYPE_INT32),
    "mono_signature_get_return_type": (1, TYPE_VOID_P),
    "mono_compile_method": (1, TYPE_VOID_P),
    "mono_free_method": (1, TYPE_VOID),
    "mono_jit_info_table_find": (2, TYPE_VOID_P),
    "mono_jit_info_get_method": (1, TYPE_VOID_P),
    "mono_jit_info_get_code_start": (1, TYPE_VOID_P),
    "mono_jit_info_get_code_size": (1, TYPE_INT32),
    "mono_jit_exec": (4, TYPE_INT32),
    "mono_method_header_get_code": (3, TYPE_VOID_P),
    "mono_disasm_code": (4, TYPE_CHAR_P),
    "mono_vtable_get_static_field_data": (1, TYPE_VOID_P),
    "mono_method_desc_new": (2, TYPE_VOID_P),
    "mono_method_desc_from_method": (1, TYPE_VOID_P),
    "mono_method_desc_free": (1, TYPE_VOID),
    "mono_string_new": (2, TYPE_VOID_P),
    "mono_string_to_utf8": (1, TYPE_CHAR_P),
    "mono_array_new": (3, TYPE_VOID_P),
    "mono_value_box": (3, TYPE_VOID_P),
    "mono_object_unbox": (1, TYPE_VOID_P),
    "mono_object_new": (2, TYPE_VOID_P),
    "mono_class_get_type": (1, TYPE_VOID_P),
    "mono_class_get_nesting_type": (1, TYPE_VOID_P),
    "mono_method_desc_search_in_image": (2, TYPE_VOID_P),
    "mono_runtime_invoke": (4, TYPE_VOID_P),
    "mono_runtime_object_init": (1, TYPE_VOID_P),
    "mono_assembly_name_new": (1, TYPE_VOID_P),
    "mono_assembly_loaded": (1, TYPE_VOID_P),
    "mono_assembly_open": (2, TYPE_VOID_P),
    "mono_image_open": (2, TYPE_VOID_P),
    "mono_field_static_get_value": (3, TYPE_VOID_P),
    "mono_field_static_set_value": (3, TYPE_VOID_P),
    "mono_class_get_field_from_name": (2, TYPE_VOID_P),
    "mono_method_get_flags": (2, TYPE_UINT32),
    "mono_type_get_class": (1, TYPE_VOID_P),
}

il2cpp_native_func_property = {
    "g_free": (1, TYPE_VOID),
    "mono_free": (1, TYPE_VOID),
    "mono_get_root_domain": (0, TYPE_VOID_P),
    "mono_thread_attach": (1, TYPE_VOID_P),
    "mono_thread_detach": (1, TYPE_VOID),
    "mono_object_get_class": (1, TYPE_VOID_P),
    "mono_domain_foreach": (2, TYPE_VOID),
    "mono_domain_set": (2, TYPE_INT32),
    "mono_domain_get": (0, TYPE_VOID_P),
    "mono_assembly_foreach": (2, TYPE_INT32),
    "mono_assembly_get_image": (1, TYPE_VOID_P),
    "mono_image_get_assembly": (1, TYPE_VOID_P),
    "mono_image_get_name": (1, TYPE_CHAR_P),
    "mono_image_get_table_info": (2, TYPE_VOID_P),
    "mono_image_rva_map": (2, TYPE_VOID_P),
    "mono_table_info_get_rows": (1, TYPE_INT32),
    "mono_metadata_decode_row_col": (3, TYPE_INT32),
    "mono_metadata_string_heap": (2, TYPE_CHAR_P),
    "mono_class_get": (2, TYPE_VOID_P),
    "mono_class_from_typeref": (2, TYPE_VOID_P),
    "mono_class_name_from_token": (2, TYPE_CHAR_P),
    "mono_class_from_name_case": (3, TYPE_VOID_P),
    "mono_class_from_name": (3, TYPE_VOID_P),
    "mono_class_get_name": (1, TYPE_CHAR_P),
    "mono_class_get_flags": (1, TYPE_INT32),
    "mono_class_get_namespace": (1, TYPE_CHAR_P),
    "mono_class_get_methods": (2, TYPE_VOID_P),
    "mono_class_get_method_from_name": (3, TYPE_VOID_P),
    "mono_class_get_fields": (2, TYPE_VOID_P),
    "mono_class_get_parent": (1, TYPE_VOID_P),
    "mono_class_get_image": (1, TYPE_VOID_P),
    "mono_class_is_generic": (1, TYPE_INT32),
    "mono_class_vtable": (2, TYPE_VOID_P),
    "mono_class_from_mono_type": (1, TYPE_VOID_P),
    "mono_class_get_element_class": (1, TYPE_VOID_P),
    "mono_class_instance_size": (1, TYPE_INT32),
    "mono_class_num_fields": (1, TYPE_INT32),
    "mono_class_num_methods": (1, TYPE_INT32),
    "mono_field_get_name": (1, TYPE_CHAR_P),
    "mono_field_get_type": (1, TYPE_VOID_P),
    "mono_field_get_parent": (1, TYPE_VOID_P),
    "mono_field_get_offset": (1, TYPE_INT32),
    "mono_field_get_flags": (1, TYPE_INT32),
    "mono_type_get_name": (1, TYPE_CHAR_P),
    "mono_type_get_type": (1, TYPE_INT32),
    "mono_type_get_name_full": (2, TYPE_CHAR_P),
    "mono_method_get_name": (1, TYPE_CHAR_P),
    "mono_method_get_class": (1, TYPE_VOID_P),
    "mono_method_get_header": (1, TYPE_VOID_P),
    "mono_method_signature": (1, TYPE_VOID_P),
    "mono_method_get_param_names": (2, TYPE_VOID_P),
    "mono_signature_get_desc": (2, TYPE_CHAR_P),
    "mono_signature_get_params": (2, TYPE_VOID_P),
    "mono_signature_get_param_count": (1, TYPE_INT32),
    "mono_signature_get_return_type": (1, TYPE_VOID_P),
    "mono_compile_method": (1, TYPE_VOID_P),
    "mono_free_method": (1, TYPE_VOID),
    "mono_jit_info_table_find": (2, TYPE_VOID_P),
    "mono_jit_info_get_method": (1, TYPE_VOID_P),
    "mono_jit_info_get_code_start": (1, TYPE_VOID_P),
    "mono_jit_info_get_code_size": (1, TYPE_INT32),
    "mono_jit_exec": (4, TYPE_INT32),
    "mono_method_header_get_code": (3, TYPE_VOID_P),
    "mono_disasm_code": (4, TYPE_CHAR_P),
    "mono_vtable_get_static_field_data": (1, TYPE_VOID_P),
    "mono_method_desc_new": (2, TYPE_VOID_P),
    "mono_method_desc_from_method": (1, TYPE_VOID_P),
    "mono_method_desc_free": (1, TYPE_VOID),
    "mono_string_new": (2, TYPE_VOID_P),
    "mono_string_to_utf8": (1, TYPE_CHAR_P),
    "mono_array_new": (3, TYPE_VOID_P),
    "mono_value_box": (3, TYPE_VOID_P),
    "mono_object_unbox": (1, TYPE_VOID_P),
    "mono_object_new": (2, TYPE_VOID_P),
    "mono_class_get_type": (1, TYPE_VOID_P),
    "mono_class_get_nesting_type": (1, TYPE_VOID_P),
    "mono_method_desc_search_in_image": (2, TYPE_VOID_P),
    "mono_runtime_invoke": (4, TYPE_VOID_P),
    "mono_runtime_object_init": (1, TYPE_VOID_P),
    "mono_assembly_name_new": (1, TYPE_VOID_P),
    "mono_assembly_loaded": (1, TYPE_VOID_P),
    "mono_assembly_open": (2, TYPE_VOID_P),
    "mono_image_open": (2, TYPE_VOID_P),
    "mono_image_get_filename": (1, TYPE_CHAR_P),
    "mono_class_get_field_from_name": (2, TYPE_VOID_P),
    "mono_method_get_flags": (2, TYPE_UINT32),
    "mono_type_get_class": (1, TYPE_VOID_P),
    "il2cpp_field_static_get_value": (2, TYPE_VOID_P),
    "il2cpp_field_static_set_value": (2, TYPE_VOID_P),
    "il2cpp_domain_get_assemblies": (2, TYPE_VOID_P),
    "il2cpp_image_get_class_count": (1, TYPE_INT32),
    "il2cpp_image_get_class": (2, TYPE_VOID_P),
    "il2cpp_type_get_assembly_qualified_name": (1, TYPE_CHAR_P),
    "il2cpp_method_get_param_count": (1, TYPE_INT32),
    "il2cpp_method_get_param_name": (2, TYPE_CHAR_P),
    "il2cpp_method_get_param": (2, TYPE_VOID_P),
    "il2cpp_method_get_return_type": (1, TYPE_VOID_P),
    "il2cpp_class_from_type": (1, TYPE_VOID_P),
    "il2cpp_string_chars": (1, TYPE_VOID_P),
}

cs_type_map = {
    "System.Void": TYPE_VOID,
    "System.Boolean": TYPE_BOOL,
    "System.SByte": TYPE_CHAR,
    "System.Byte": TYPE_UCHAR,
    "System.Int16": TYPE_INT16,
    "System.UInt16": TYPE_UINT16,
    "System.Int32": TYPE_INT32,
    "System.UInt32": TYPE_UINT32,
    "System.Int64": TYPE_INT64,
    "System.UInt64": TYPE_UINT64,
    "System.Single": TYPE_FLOAT,
    "System.Double": TYPE_DOUBLE,
    "System.String": TYPE_CS_STRING,
    "System.Decimal": -1,
}

frida_type_map = {
    TYPE_BOOL: "uint8",
    TYPE_CHAR: "int8",
    TYPE_UCHAR: "uint8",
    TYPE_INT16: "int16",
    TYPE_UINT16: "uint16",
    TYPE_INT32: "int32",
    TYPE_UINT32: "uint32",
    TYPE_INT64: "int64",
    TYPE_UINT64: "uint64",
    TYPE_FLOAT: "float",
    TYPE_DOUBLE: "double",
    TYPE_VOID_P: "pointer",
    TYPE_CHAR_P: "pointer",
    TYPE_CS_STRING: "pointer",
}

protection_map = {
    "---": PAGE_NOACCESS,
    "r--": PAGE_READONLY,
    "rw-": PAGE_READWRITE,
    "--x": PAGE_EXECUTE,
    "r-x": PAGE_EXECUTE_READ,
    "rwx": PAGE_EXECUTE_READWRITE,
}

protection_rev_map = {
    PAGE_NOACCESS: "---",
    PAGE_READONLY: "r--",
    PAGE_READWRITE: "rw-",
    PAGE_EXECUTE: "--x",
    PAGE_EXECUTE_READ: "r-x",
    PAGE_EXECUTE_READWRITE: "rwx",
}
