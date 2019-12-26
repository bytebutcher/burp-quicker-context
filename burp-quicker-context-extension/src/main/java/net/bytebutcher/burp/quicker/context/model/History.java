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

    public String getCurrent() {
        if (index != -1) {
            return history.get(index);
        }
        return null;
    }

    public String getNext() {
        if (index != -1) {
            this.index = Math.floorMod(++this.index, history.size());
            return history.get(this.index);
        }
        return null;
    }

    public String getPrevious() {
        if (index != -1) {
            this.index = Math.floorMod(--this.index, history.size());
            return history.get(this.index);
        }
        return null;
    }

    public boolean isEmpty() {
        return history.isEmpty();
    }
}
