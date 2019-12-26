package net.bytebutcher.burp.quicker.context.model;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import com.google.common.collect.Lists;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

public class Config {

    private final IBurpExtenderCallbacks callbacks;
    private BurpExtender burpExtender;
    private String quicker_context_history = "Quicker.Context.History";

    public Config(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.getCallbacks();
    }

    public List<String> loadHistory() {
        String history = this.callbacks.loadExtensionSetting(quicker_context_history);
        Type listType = new TypeToken<ArrayList<String>>(){}.getType();
        List<String> selectionHistory = new Gson().fromJson(history, listType);
        if (selectionHistory == null) {
            return Lists.newArrayList();
        } else {
            return selectionHistory;
        }
    }

    public void saveHistory(List<String> selectionHistory) {
        this.callbacks.saveExtensionSetting(quicker_context_history, new Gson().toJson(selectionHistory));
    }

}