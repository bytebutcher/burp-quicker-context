package net.bytebutcher.burp.quicker.context.gui.widget.combobox;
import com.google.common.collect.Lists;
import me.xdrop.fuzzywuzzy.FuzzySearch;

import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

public class FilterComboBox<E> extends JComboBox<E> {
    protected List<E> entries;

    public FilterComboBox() {
        super();
        entries = Lists.newArrayList();
        this.setEditable(true);
        setupKeyListener(this.getEditor().getEditorComponent());
    }

    private void setupKeyListener(Component editorComponent) {
        final JTextField textfield = (JTextField) editorComponent;
        textfield.addKeyListener(new KeyAdapter() {
            public void keyTyped(KeyEvent e) {
                SwingUtilities.invokeLater(() -> comboFilter(textfield.getText()));
            }
        });
    }

    @Override
    public void setEditor(ComboBoxEditor anEditor) {
        super.setEditor(anEditor);
        setupKeyListener(anEditor.getEditorComponent());
    }

    protected FilterComboBox(ComboBoxModel<E> aModel) {
        super(aModel);
    }

    protected FilterComboBox(E[] m) {
        super(m);
    }

    @Override
    public void addItem(E item) {
        super.addItem(item);
        entries.add(item);
    }

    @Override
    public void removeAllItems() {
        super.removeAllItems();
        entries.clear();
    }

    @Override
    public void removeItem(Object anObject) {
        super.removeItem(anObject);
        entries.remove(anObject);
    }

    @Override
    public void removeItemAt(int anIndex) {
        super.removeItemAt(anIndex);
        entries.remove(anIndex);
    }

    public List<E> getFilteredEntries(String enteredText) {
        List<String> choices = entries.stream().map(Object::toString).collect(Collectors.toList());
        return FuzzySearch.extractSorted(enteredText, choices, 40).stream().map(e -> entries.get(e.getIndex())).collect(Collectors.toList());
    }

    public void comboFilter(String enteredText) {
        List<E> entriesFiltered = getFilteredEntries(enteredText);
        if (entriesFiltered.size() > 0) {
            this.setModel(new DefaultComboBoxModel(entriesFiltered.toArray()));
            this.setSelectedItem(enteredText);
            this.showPopup();
        } else {
            this.hidePopup();
        }
    }
}