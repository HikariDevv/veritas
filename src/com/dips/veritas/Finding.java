package com.dips.veritas;

import java.util.List;

public final class Finding {
    private final String category;
    private final String severity;
    private final int weight;
    private final String title;
    private final String location;
    private final List<String> details;

    public Finding(String category, String severity, int weight, String title, String location, List<String> details) {
        this.category = category;
        this.severity = severity;
        this.weight = weight;
        this.title = title;
        this.location = location;
        this.details = details;
    }

    public String category() {
        return category;
    }

    public String severity() {
        return severity;
    }

    public int weight() {
        return weight;
    }

    public String title() {
        return title;
    }

    public String location() {
        return location;
    }

    public List<String> details() {
        return details;
    }
}
