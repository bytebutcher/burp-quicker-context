package net.bytebutcher.burp.quicker.context.gui.util;

import java.util.Map;
import java.util.HashMap;
import java.util.Collection;
import java.lang.reflect.Field;
import java.awt.Color;

/**
 * Burp color names. It's intended use is for parsing a name and return the
 * corresponding color or return a name for a given color.
 *
 * This code is based on HTMLColors by Adrian Ber.
 */
public class BurpColorUtil {

    /** Don't instantiate this, use only the static methods */
    private BurpColorUtil() {
    }

    /** map between color names and colors;
     * tough there are fields for every color we use a map because is a faster
     * way to get the color
     */
    private static Map<String, Color> name2color = new HashMap<String, Color>();
    /** map between colors and color names;
     * tough there are fields for every color we use a map because is a faster
     * way to get the color
     */
    private static Map<Color, String> color2name = new HashMap<Color, String>();

    /** Initialiase colors map */
    private static void initColorsMap() {
        Field[] fields = BurpColorUtil.class.getFields();
        for (Field field : fields) {
            if (field.getType().isAssignableFrom(Color.class)) {
                addColor(field.getName());
            }
        }
    }

    /** Used to initialize the map */
    private static void addColor(String colorName, Color color) {
        name2color.put(colorName, color);
        color2name.put(color, colorName);
    }

    /** Used to initialize the map */
    private static void addColor(String colorName) {
        addColor(colorName, getColorFromField(colorName));
    }

    /** Used to initialize the map */
    private static void addColor(String colorName, int colorRGB) {
        addColor(colorName, new Color(colorRGB));
    }

    /** Returns a color with the specified case-insensitive name. */
    private static Color getColorFromField(String name) {
        try {
            Field colorField = BurpColorUtil.class.getField(name.toLowerCase());
            return (Color) colorField.get(BurpColorUtil.class);
        }
        catch (NoSuchFieldException exc) {
        }
        catch (SecurityException exc) {
        }
        catch (IllegalAccessException exc) {
        }
        catch (IllegalArgumentException exc) {
        }
        return null;
    }

    /** Returns a color with the specified case-insensitive name.*/
    public static String getName(Color color) {
        return color2name.get(color);
    }

    /** Returns a color with the specified case-insensitive name.*/
    public static Color getColor(String name) {
        return name2color.get(name.toLowerCase());
    }

    /** Returns a collection of all color names */
    public static Collection<String> colors() {
        return name2color.keySet();
    }

    /** Transform a color string into a color object.
     *  @param s the color string
     *  @return the color object
     */
    public static Color decodeColor(String s) {
        if (s == null)
            return null;
        Color c;
        try {
            c = Color.decode(s);
        }
        catch (NumberFormatException exc) {
            c = BurpColorUtil.getColor(s);
        }
        return c;
    }

    public static final Color white = new Color(0xffffff);
    public static final Color red = new Color(0xff6464);
    public static final Color orange = new Color(0xffc864);
    public static final Color yellow = new Color(0xffff64);
    public static final Color green = new Color(0x64ff64);
    public static final Color cyan = new Color(0x64ffff);
    public static final Color blue = new Color(0x6464ff);
    public static final Color pink = new Color(0xffc8c8);
    public static final Color magenta = new Color(0xff64ff);
    public static final Color gray = new Color(0xb4b4b4);

    static {
        initColorsMap();
    }

}