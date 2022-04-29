package io.github.bananalang.compile;

import java.util.IdentityHashMap;
import java.util.Map;

import org.objectweb.asm.Label;

import io.github.bananalang.typecheck.LocalVariable;

public final class Scope {
    private final Label startLabel;
    private final int firstLocal;
    private final Map<LocalVariable, Label> varStarts;

    public Scope(int firstLocal) {
        this.startLabel = new Label();
        this.firstLocal = firstLocal;
        this.varStarts = new IdentityHashMap<>();
    }

    public Label getStartLabel() {
        return startLabel;
    }

    public int getFirstLocal() {
        return firstLocal;
    }

    public Map<LocalVariable, Label> getVarStarts() {
        return varStarts;
    }
}
