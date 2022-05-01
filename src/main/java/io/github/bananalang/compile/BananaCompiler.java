package io.github.bananalang.compile;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.InstructionAdapter;

import io.github.bananalang.parse.Parser;
import io.github.bananalang.parse.Tokenizer;
import io.github.bananalang.parse.ast.AccessExpression;
import io.github.bananalang.parse.ast.AssignmentExpression;
import io.github.bananalang.parse.ast.BinaryExpression;
import io.github.bananalang.parse.ast.CallExpression;
import io.github.bananalang.parse.ast.ExpressionNode;
import io.github.bananalang.parse.ast.ExpressionStatement;
import io.github.bananalang.parse.ast.FunctionDefinitionStatement;
import io.github.bananalang.parse.ast.IdentifierExpression;
import io.github.bananalang.parse.ast.IfOrWhileStatement;
import io.github.bananalang.parse.ast.ImportStatement;
import io.github.bananalang.parse.ast.NullExpression;
import io.github.bananalang.parse.ast.ReturnStatement;
import io.github.bananalang.parse.ast.StatementList;
import io.github.bananalang.parse.ast.StatementNode;
import io.github.bananalang.parse.ast.StringExpression;
import io.github.bananalang.parse.ast.VariableDeclarationStatement;
import io.github.bananalang.parse.ast.VariableDeclarationStatement.VariableDeclaration;
import io.github.bananalang.parse.token.Token;
import io.github.bananalang.typecheck.EvaluatedType;
import io.github.bananalang.typecheck.LocalVariable;
import io.github.bananalang.typecheck.MethodCall;
import io.github.bananalang.typecheck.ScriptMethod;
import io.github.bananalang.typecheck.Typechecker;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.LoaderClassPath;
import javassist.Modifier;
import javassist.bytecode.Descriptor;

public final class BananaCompiler {
    private static final String NULLABLE_ANNOTATION = "Lbanana/internal/annotation/Nullable;";
    private static final String NONNULL_ANNOTATION = "Lbanana/internal/annotation/NonNull;";

    private final Typechecker types;
    private final StatementList root;
    private final CompileOptions options;
    private ClassWriter result;

    private final Deque<Map.Entry<StatementList, Scope>> scopes = new ArrayDeque<>();
    private int currentLineNumber;
    private Label currentLineNumberLabel;
    private int currentVariableDecl;

    private BananaCompiler(Typechecker types, StatementList root, CompileOptions options) {
        this.types = types;
        this.root = root;
        this.options = options;
        this.result = null;
    }

    public static ClassWriter compileFile(File file, CompileOptions options) throws IOException {
        try (FileReader reader = new FileReader(file)) {
            return compile(reader, options);
        }
    }

    public static ClassWriter compileFile(String fileName, CompileOptions options) throws IOException {
        try (FileReader reader = new FileReader(fileName)) {
            return compile(reader, options);
        }
    }

    public static ClassWriter compile(Reader inputReader, CompileOptions options) throws IOException {
        return compile(new Parser(inputReader), options);
    }

    public static ClassWriter compile(String source, CompileOptions options) throws IOException {
        return compile(new Parser(source), options);
    }

    public static ClassWriter compile(Tokenizer tokenizer, CompileOptions options) throws IOException {
        return compile(new Parser(tokenizer), options);
    }

    public static ClassWriter compile(List<Token> tokens, CompileOptions options) throws IOException {
        return compile(new Parser(tokens), options);
    }

    public static ClassWriter compile(Parser parser, CompileOptions options) throws IOException {
        StatementList root = parser.parse();
        ClassPool cp = new ClassPool(ClassPool.getDefault());
        cp.appendClassPath(new LoaderClassPath(BananaCompiler.class.getClassLoader()));
        Typechecker typechecker = new Typechecker(cp);
        typechecker.typecheck(root);
        return compile(typechecker, root, options);
    }

    public static ClassWriter compile(Typechecker types, StatementList ast, CompileOptions options) {
        BananaCompiler compiler = new BananaCompiler(types, ast, options);
        return compiler.compile();
    }

    private ClassWriter compile() {
        if (result == null) {
            result = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            result.visit(52, Opcodes.ACC_PUBLIC, options.className(), null, "java/lang/Object", null);
            result.visitSource(options.sourceFileName(), null);
            {
                MethodVisitor initMethod = result.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
                initMethod.visitCode();
                initMethod.visitVarInsn(Opcodes.ALOAD, 0);
                initMethod.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
                initMethod.visitInsn(Opcodes.RETURN);
                initMethod.visitMaxs(-1, -1);
                initMethod.visitEnd();
            }
            for (StatementNode child : root.children) {
                if (child instanceof FunctionDefinitionStatement) {
                    FunctionDefinitionStatement functionDefinition = (FunctionDefinitionStatement)child;
                    ScriptMethod methodDefinition = types.getMethodDefinition(functionDefinition);
                    StringBuilder descriptor = new StringBuilder("(");
                    for (EvaluatedType arg : methodDefinition.getArgTypes()) {
                        descriptor.append(arg.getDescriptor());
                    }
                    descriptor.append(')').append(methodDefinition.getReturnType().getDescriptor());
                    MethodVisitor mv = result.visitMethod(
                        Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                        functionDefinition.name,
                        descriptor.toString(),
                        null,
                        null
                    );
                    if (!methodDefinition.getReturnType().getName().equals("void")) {
                        mv.visitAnnotation(
                            methodDefinition.getReturnType().isNullable()
                                ? NULLABLE_ANNOTATION
                                : NONNULL_ANNOTATION,
                            false
                        );
                    }
                    currentVariableDecl = 0;
                    for (VariableDeclaration arg : functionDefinition.args) {
                        if (arg.value != null) {
                            throw new RuntimeException("Default parameters not supported yet");
                        }
                        EvaluatedType type = methodDefinition.getArgTypes()[currentVariableDecl];
                        mv.visitParameter(arg.name, 0);
                        mv.visitParameterAnnotation(
                            currentVariableDecl,
                            type.isNullable() ? NULLABLE_ANNOTATION : NONNULL_ANNOTATION,
                            false
                        );
                        addLocal(arg.name, currentVariableDecl++);
                    }
                    mv.visitCode();
                    if (compileStatementList(
                        new InstructionAdapter(mv),
                        functionDefinition.body,
                        functionDefinition.args,
                        true,
                        true
                    )) {
                        if (methodDefinition.getReturnType().getName().equals("void")) {
                            mv.visitInsn(Opcodes.RETURN);
                        } else {
                            mv.visitInsn(Opcodes.ACONST_NULL);
                            mv.visitInsn(Opcodes.ARETURN);
                        }
                    }
                    mv.visitMaxs(-1, -1);
                    mv.visitEnd();
                }
            }
            if (needsMainMethod()) {
                MethodVisitor mainMethod = result.visitMethod(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "main",
                    "([Ljava/lang/String;)V",
                    null,
                    null
                );
                mainMethod.visitParameter("args", 0);
                mainMethod.visitCode();
                currentVariableDecl = 1;
                if (compileStatementList(new InstructionAdapter(mainMethod), root, null, true, true)) {
                    mainMethod.visitInsn(Opcodes.RETURN);
                }
                mainMethod.visitMaxs(-1, -1);
                mainMethod.visitEnd();
            }
            result.visitEnd();
        }
        return result;
    }

    private boolean needsMainMethod() {
        for (StatementNode child : root.children) {
            if (child instanceof ImportStatement) continue;
            if (child instanceof FunctionDefinitionStatement) continue;
            return true;
        }
        return false;
    }

    private boolean compileStatement(InstructionAdapter method, StatementNode stmt) {
        if (stmt instanceof StatementList) {
            compileStatementList(method, (StatementList)stmt, null, false, false);
        } else if (stmt instanceof IfOrWhileStatement) {
            return compileIfOrWhileStatement(method, (IfOrWhileStatement)stmt);
        } else if (stmt instanceof ExpressionStatement) {
            compileExpressionStatement(method, (ExpressionStatement)stmt);
        } else if (stmt instanceof VariableDeclarationStatement) {
            compileVariableDeclarationStatement(method, (VariableDeclarationStatement)stmt);
        } else if (stmt instanceof ReturnStatement) {
            compileReturnStatement(method, (ReturnStatement)stmt);
            return true;
        } else if (!(stmt instanceof ImportStatement) && !(stmt instanceof FunctionDefinitionStatement)) {
            throw new IllegalArgumentException(stmt.getClass().getSimpleName() + " not supported for compilation yet");
        }
        return false;
    }

    private boolean compileStatementList(
        InstructionAdapter method,
        StatementList node,
        VariableDeclaration[] args,
        boolean skipMethods,
        boolean isTopLevel
    ) {
        scopes.addLast(new SimpleImmutableEntry<>(node, new Scope(currentVariableDecl)));
        Scope scope = scopes.getLast().getValue();
        method.visitLabel(scope.getStartLabel());
        if (args != null) {
            Map<String, LocalVariable> localVarScope = types.getScope(node);
            for (VariableDeclaration arg : args) {
                scope.getVarStarts().put(localVarScope.get(arg.name), scope.getStartLabel());
            }
        }
        for (int i = 0; i < node.children.size(); i++) {
            StatementNode child = node.children.get(i);
            if (compileStatement(method, child)) {
                if (i < node.children.size() - 1) {
                    throw new IllegalArgumentException("Unreachable code detected");
                }
                return false;
            }
        }
        endScope(method);
        return true;
    }

    private void endScope(InstructionAdapter method) {
        Map.Entry<StatementList, Scope> scope = scopes.removeLast();
        currentVariableDecl = scope.getValue().getFirstLocal();
        Label endLabel = new Label();
        method.visitLabel(endLabel);
        for (Map.Entry<String, LocalVariable> variable : types.getScope(scope.getKey()).entrySet()) {
            method.visitLocalVariable(
                variable.getKey(),
                variable.getValue().getType().getDescriptor(),
                null,
                scope.getValue().getVarStarts().get(variable.getValue()),
                endLabel,
                variable.getValue().getIndex() + currentVariableDecl
            );
        }
    }

    private boolean compileIfOrWhileStatement(InstructionAdapter method, IfOrWhileStatement stmt) {
        Label conditionLabel = null;
        if (stmt.isWhile) {
            conditionLabel = new Label();
            method.visitLabel(conditionLabel);
        }
        Label endLabelWithPop = new Label();
        Label endLabelNoPop = new Label();
        compileExpression(method, stmt.condition);
        EvaluatedType expressionType = types.getType(stmt.condition);
        lineNumber(stmt.row, method);
        MethodCall handler = types.getMethodCall(stmt);
        if (expressionType.isNullable()) {
            if (handler != null) {
                method.dup();
                method.ifnull(endLabelWithPop);
            } else {
                method.ifnull(endLabelNoPop);
            }
        }
        boolean neverending = false;
        if (handler != null) {
            CtClass declaringClass = handler.getJavaMethod().getDeclaringClass();
            boolean isInterface = declaringClass.isInterface();
            method.visitMethodInsn(
                isInterface ? Opcodes.INVOKEINTERFACE : Opcodes.INVOKEVIRTUAL,
                Descriptor.toJvmName(declaringClass),
                handler.getName(),
                handler.getJavaMethod().getSignature(),
                isInterface
            );
            if (handler.getName().equals("truthy")) {
                method.ifeq(endLabelNoPop);
            } else {
                method.ifne(endLabelNoPop);
            }
        } else if (!expressionType.isNullable()) {
            method.pop();
            if (stmt.isWhile) {
                neverending = true;
            }
        }
        compileStatement(method, stmt.body);
        Label endElseLabel = new Label();
        if (stmt.isWhile) {
            method.goTo(conditionLabel);
        } else if (stmt.elseBody != null) {
            method.goTo(endElseLabel);
        }
        if (expressionType.isNullable() && handler != null) {
            if (!stmt.isWhile) {
                if (stmt.elseBody == null) {
                    method.goTo(endLabelNoPop);
                }
            }
            method.visitLabel(endLabelWithPop);
            method.pop();
        }
        if (neverending) {
            endScope(method);
            return true;
        }
        method.visitLabel(endLabelNoPop);
        if (stmt.elseBody != null) {
            compileStatement(method, stmt.elseBody);
            method.visitLabel(endElseLabel);
        }
        return false;
    }

    private void compileExpressionStatement(InstructionAdapter method, ExpressionStatement stmt) {
        if (stmt.expression instanceof AssignmentExpression) {
            compileAssignmentExpression(method, (AssignmentExpression)stmt.expression, false);
        } else {
            compileExpression(method, stmt.expression);
            if (!types.getType(stmt.expression).getName().equals("void")) {
                lineNumber(stmt.row, method);
                method.pop();
            }
        }
    }

    private void compileVariableDeclarationStatement(InstructionAdapter method, VariableDeclarationStatement stmt) {
        Label label = new Label();
        method.visitLabel(label);
        for (VariableDeclaration decl : stmt.declarations) {
            addLocal(decl.name, currentVariableDecl);
            Map.Entry<StatementList, Scope> scope = scopes.getLast();
            scope.getValue().getVarStarts().put(types.getScope(scope.getKey()).get(decl.name), label);
            if (decl.value != null) {
                compileExpression(method, decl.value);
                lineNumber(stmt.row, method);
                method.visitVarInsn(Opcodes.ASTORE, currentVariableDecl);
            }
            currentVariableDecl++;
        }
    }

    private void compileReturnStatement(InstructionAdapter method, ReturnStatement stmt) {
        if (stmt.value == null) {
            endScope(method);
            lineNumber(stmt.row, method);
            method.visitInsn(Opcodes.RETURN);
            return;
        }
        compileExpression(method, stmt.value);
        endScope(method);
        lineNumber(stmt.row, method);
        method.visitInsn(Opcodes.ARETURN);
    }

    private void compileExpression(InstructionAdapter method, ExpressionNode expr) {
        if (expr instanceof StringExpression) {
            lineNumber(expr.row, method);
            method.aconst(((StringExpression)expr).value);
        } else if (expr instanceof NullExpression) {
            lineNumber(expr.row, method);
            method.aconst(null);
        } else if (expr instanceof CallExpression) {
            CallExpression callExpr = (CallExpression)expr;
            MethodCall methodToCall = types.getMethodCall(callExpr);
            int opcode;
            String ownerName, descriptor;
            Label safeNavigationLabel = null;
            if (methodToCall.isScriptMethod()) {
                for (ExpressionNode arg : callExpr.args) {
                    compileExpression(method, arg);
                }
                ScriptMethod scriptMethod = methodToCall.getScriptMethod();
                opcode = Opcodes.INVOKESTATIC;
                ownerName = options.className();
                StringBuilder descriptorBuilder = new StringBuilder("(");
                for (EvaluatedType argType : scriptMethod.getArgTypes()) {
                    descriptorBuilder.append(argType.getDescriptor());
                }
                descriptor = descriptorBuilder.append(')')
                    .append(scriptMethod.getReturnType().getDescriptor())
                    .toString();
            } else {
                CtMethod javaMethod = methodToCall.getJavaMethod();
                boolean isStatic = Modifier.isStatic(javaMethod.getModifiers());
                if (callExpr.target instanceof AccessExpression && !isStatic) {
                    AccessExpression accessExpr = (AccessExpression)callExpr.target;
                    compileExpression(method, accessExpr.target);
                    if (accessExpr.safeNavigation) {
                        safeNavigationLabel = new Label();
                        method.dup();
                        method.ifnull(safeNavigationLabel);
                    }
                }
                descriptor = javaMethod.getSignature();
                if (Modifier.isVarArgs(javaMethod.getModifiers())) {
                    int actualArgCount = Descriptor.numOfParameters(descriptor);
                    for (int i = 0; i < actualArgCount - 1; i++) {
                        compileExpression(method, callExpr.args[i]);
                    }
                    method.iconst(callExpr.args.length - actualArgCount + 1);
                    int endParen = descriptor.indexOf(')');
                    String arrType = descriptor.substring(descriptor.lastIndexOf('L', endParen - 2) + 1, endParen - 1);
                    method.visitTypeInsn(Opcodes.ANEWARRAY, arrType);
                    for (int i = actualArgCount - 1; i < callExpr.args.length; i++) {
                        method.dup();
                        method.iconst(i - actualArgCount + 1);
                        compileExpression(method, callExpr.args[i]);
                        method.visitInsn(Opcodes.AASTORE);
                    }
                } else {
                    for (ExpressionNode arg : callExpr.args) {
                        compileExpression(method, arg);
                    }
                }
                opcode = isStatic
                    ? Opcodes.INVOKESTATIC
                    : (javaMethod.getDeclaringClass().isInterface()
                        ? Opcodes.INVOKEINTERFACE
                        : Opcodes.INVOKEVIRTUAL);
                ownerName = Descriptor.toJvmName(javaMethod.getDeclaringClass());
            }
            lineNumber(expr.row, method);
            method.visitMethodInsn(
                opcode,
                ownerName,
                methodToCall.getName(),
                descriptor,
                opcode == Opcodes.INVOKEINTERFACE
            );
            if (safeNavigationLabel != null) {
                method.visitLabel(safeNavigationLabel);
            }
        } else if (expr instanceof IdentifierExpression) {
            IdentifierExpression identExpr = (IdentifierExpression)expr;
            lineNumber(expr.row, method);
            method.visitVarInsn(Opcodes.ALOAD, findLocal(identExpr.identifier));
        } else if (expr instanceof BinaryExpression) {
            BinaryExpression binExpr = (BinaryExpression)expr;
            switch (binExpr.type) {
                case NULL_COALESCE: {
                    compileExpression(method, binExpr.left);
                    Label endLabel = new Label();
                    method.dup();
                    method.ifnonnull(endLabel);
                    method.pop();
                    compileExpression(method, binExpr.right);
                    method.visitLabel(endLabel);
                    break;
                }
                default:
                    throw new AssertionError(binExpr.type);
            }
        } else if (expr instanceof AssignmentExpression) {
            compileAssignmentExpression(method, (AssignmentExpression)expr, true);
        } else {
            throw new IllegalArgumentException(expr.getClass().getSimpleName() + " not supported for compilation yet");
        }
    }

    private void compileAssignmentExpression(InstructionAdapter method, AssignmentExpression expr, boolean dup) {
        compileExpression(method, expr.value);
        if (expr.target instanceof IdentifierExpression) {
            lineNumber(expr.row, method);
            if (dup) {
                method.dup();
            }
            method.visitVarInsn(Opcodes.ASTORE, findLocal(((IdentifierExpression)expr.target).identifier));
        } else {
            throw new IllegalArgumentException(
                "Can't assign to " + expr.target.getClass().getSimpleName() + " yet"
            );
        }
    }

    private void addLocal(String name, int index) {
        scopes.getLast().getValue().getLocals().put(name, index);
    }

    private int findLocal(String name) {
        Iterator<Map.Entry<StatementList, Scope>> iterator = scopes.descendingIterator();
        while (iterator.hasNext()) {
            Scope scope = iterator.next().getValue();
            Integer local = scope.getLocals().get(name);
            if (local != null) {
                return local;
            }
        }
        return -1; // Shouldn't happen!
    }

    private void lineNumber(int line, InstructionAdapter method) {
        if (line != currentLineNumber) {
            currentLineNumber = line;
            method.visitLabel(currentLineNumberLabel = new Label());
            method.visitLineNumber(line, currentLineNumberLabel);
        }
    }
}
