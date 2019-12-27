package net.bytebutcher.burp.quicker.context.model;

import burp.BurpExtender;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class History {

    private List<String> history;
    private int index;

    public History(Set<String> contextMenuEntries, BurpExtender burpExtender) {
        this.history = burpExtender.getConfig().loadHistory().stream().filter(contextMenuEntries::contains).collect(Collectors.toList());;
        this.index = history.size() - 1; // might be -1;
    }

    public History next() {
        if (index != -1) {
            this.index = Math.floorMod(++this.index, history.size());
        }
        return this;
    }

    public History previous() {
        if (index != -1) {
            this.index = Math.floorMod(--this.index, history.size());
        }
        return this;
    }

    public boolean isEmpty() {
        return history.isEmpty();
    }

    @Override
    public String toString() {
        if (index != -1) {
            return history.get(index);
        }
        return null;
    }

}
