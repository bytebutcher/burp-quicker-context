# Burp-Quicker-Extension

This extension adds the "Quicker..." context menu entry which opens a lightweight dialog to select all available context menu entries more easily by typing parts of the name or choosing one stored in the history.

![Quicker Context Dialog](images/quicker-context-dialog.png)

## Usage

The Quicker Context Dialog can be completely controlled using the keyboard:

* ARROW-UP/ARROW-DOWN: Select context menu entry in list
* ENTER: Run selected contex menu entry
* CTRL+TAB: Next context menu entry in history
* CTRL+SHIFT+TAB: Previous context menu entry in history
* ESCAPE: Close the dialog

## Build

This project was built using IntelliJ and Gradle. When you make changes to the source (and especially the GUI) you should apply following settings within Intellij to make sure that everything builds successfully:
* File -> Settings -> Editor -> GUI Designer -> Generate GUI into: Java source
* File -> Settings -> Build, Execution, Deployment -> Compiler -> Build project automatically

When the GUI is not updated correctly you may rebuild the project manually:
* Build -> Rebuild Project

After that you can execute the "fatJar"-task within the "build.gradle"-file. This will produce a jar in the "build/libs/" directory called "burp-send-to-extension-{version}.jar".
