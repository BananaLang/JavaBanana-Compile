package io.github.bananalang.compile;

import java.io.File;
import java.util.Objects;

public final class CompileOptions {
    public static final CompileOptions DEFAULT = new CompileOptions();

    private String sourceFileName = null;
    private String moduleName = null;
    private String className = null;

    public CompileOptions(String sourceFileName, String moduleName, String className) {
        sourceFileName(sourceFileName);
        moduleName(moduleName);
        className(className);
    }

    public CompileOptions() {
    }

    public String sourceFileName() {
        return sourceFileName;
    }

    public CompileOptions sourceFileName(String sourceFileName) {
        this.sourceFileName = sourceFileName;
        return this;
    }

    public CompileOptions defaultSourceFileName() {
        return sourceFileName(null);
    }

    public String moduleName() {
        return moduleName;
    }

    public CompileOptions moduleName(String moduleName) {
        if (moduleName == null && sourceFileName != null) {
            moduleName = fileToModuleName(sourceFileName);
        }
        this.moduleName = moduleName;
        return this;
    }

    public CompileOptions defaultModuleName() {
        return moduleName(null);
    }

    public String className() {
        return className;
    }

    public CompileOptions className(String className) {
        if (className == null && moduleName != null) {
            className = moduleToClassName(moduleName);
        }
        this.className = className;
        return this;
    }

    public CompileOptions defaultClassName() {
        return className(null);
    }

    public String classFileName() {
        return className.replace('.', '/').concat(".class");
    }

    public static String fileToModuleName(String fileName) {
        if (!Objects.requireNonNull(fileName, "fileName").endsWith(".ba") || fileName.indexOf('\0') != -1) {
            throw new IllegalArgumentException(fileName);
        }
        fileName = fileName.substring(0, fileName.length() - 3);
        if (fileName.isEmpty()) {
            throw new IllegalArgumentException(fileName);
        }
        return fileName.replace(File.separatorChar, '/').replace('/', '.'); // Handle both / and File.separatorChar
    }

    public static String moduleToClassName(String moduleName) {
        if (Objects.requireNonNull(moduleName, "moduleName").isEmpty()) {
            throw new IllegalArgumentException(moduleName);
        }
        int dotIndex = moduleName.lastIndexOf('.');
        if (dotIndex == -1) {
            return "Module" + Character.toUpperCase(moduleName.charAt(0)) + moduleName.substring(1);
        }
        return moduleName.substring(0, dotIndex)
            + ".Module"
            + Character.toUpperCase(moduleName.charAt(dotIndex + 1))
            + moduleName.substring(dotIndex + 2);
    }
}
