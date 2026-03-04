package it.amhs.service;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class X411DiagnosticMapper {

    private static final String DEFAULT_FAILURE_CODE = "X411:31";

    private static final Pattern DIAGNOSTIC_CODE_PATTERN = Pattern.compile("(?:^|[;,\\s])diagnostic-code\\s*[=:]\\s*([0-9]{1,3})(?:$|[;,\\s])", Pattern.CASE_INSENSITIVE);

    private static final Map<String, String> KEYWORD_TO_CODE = new LinkedHashMap<>();

    static {
        KEYWORD_TO_CODE.put("timeout", "X411:16");
        KEYWORD_TO_CODE.put("timed out", "X411:16");
        KEYWORD_TO_CODE.put("loop", "X411:21");
        KEYWORD_TO_CODE.put("hop", "X411:21");
        KEYWORD_TO_CODE.put("route", "X411:22");
        KEYWORD_TO_CODE.put("unreachable", "X411:22");
        KEYWORD_TO_CODE.put("network", "X411:22");
        KEYWORD_TO_CODE.put("congestion", "X411:28");
        KEYWORD_TO_CODE.put("busy", "X411:28");
        KEYWORD_TO_CODE.put("content", "X411:26");
        KEYWORD_TO_CODE.put("encoding", "X411:26");
        KEYWORD_TO_CODE.put("security", "X411:30");
        KEYWORD_TO_CODE.put("certificate", "X411:30");
        KEYWORD_TO_CODE.put("authentication", "X411:30");
        KEYWORD_TO_CODE.put("policy", "X411:31");
        KEYWORD_TO_CODE.put("validation", "X411:31");
        KEYWORD_TO_CODE.put("rejected", "X411:31");
    }

    public String map(String reason, String diagnostic) {
        String explicit = firstX411Code(reason, diagnostic);
        if (explicit != null) {
            return explicit;
        }

        String explicitDiagnosticCode = firstDiagnosticCode(reason, diagnostic);
        if (explicitDiagnosticCode != null) {
            return explicitDiagnosticCode;
        }

        String corpus = ((reason == null ? "" : reason) + " " + (diagnostic == null ? "" : diagnostic))
            .toLowerCase(Locale.ROOT);

        for (Map.Entry<String, String> entry : KEYWORD_TO_CODE.entrySet()) {
            if (corpus.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return DEFAULT_FAILURE_CODE;
    }


    private String firstDiagnosticCode(String... values) {
        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            Matcher matcher = DIAGNOSTIC_CODE_PATTERN.matcher(value);
            if (matcher.find()) {
                return "X411:" + Integer.parseInt(matcher.group(1));
            }
        }
        return null;
    }

    private String firstX411Code(String... values) {
        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            String normalized = value.trim().toUpperCase(Locale.ROOT);
            if (normalized.matches("X411:[0-9]{1,3}")) {
                return normalized;
            }
        }
        return null;
    }
}

