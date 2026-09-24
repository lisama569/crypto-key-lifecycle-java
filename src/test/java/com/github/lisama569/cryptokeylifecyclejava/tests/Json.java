package com.github.lisama569.cryptokeylifecyclejava.tests;

/** 测试专用：极简 JSON 字符串字段提取（避免在断言中引入额外依赖）。 */
final class Json {
    private Json() { }

    static String field(String json, String name) {
        String key = "\"" + name + "\":\"";
        int start = json.indexOf(key);
        if (start < 0) {
            throw new IllegalStateException("field not found: " + name);
        }
        int from = start + key.length();
        int end = json.indexOf('"', from);
        return json.substring(from, end);
    }
}
