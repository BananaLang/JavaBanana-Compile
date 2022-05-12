package io.github.bananalang.compile;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.InstructionAdapter;

import io.github.bananalang.JavaBananaConstants;
import io.github.bananalang.compilecommon.problems.GenericCompilationFailureException;
import io.github.bananalang.compilecommon.problems.ProblemCollector;
import io.github.bananalang.parse.Parser;
import io.github.bananalang.parse.Tokenizer;
import io.github.bananalang.parse.ast.AccessExpression;
import io.github.bananalang.parse.ast.AssignmentExpression;
import io.github.bananalang.parse.ast.BinaryExpression;
import io.github.bananalang.parse.ast.CallExpression;
import io.github.bananalang.parse.ast.CastExpression;
import io.github.bananalang.parse.ast.ExpressionNode;
import io.github.bananalang.parse.ast.ExpressionStatement;
import io.github.bananalang.parse.ast.FunctionDefinitionStatement;
import io.github.bananalang.parse.ast.IdentifierExpression;
import io.github.bananalang.parse.ast.IfOrWhileStatement;
import io.github.bananalang.parse.ast.ImportStatement;
import io.github.bananalang.parse.ast.ReservedIdentifierExpression;
import io.github.bananalang.parse.ast.ReturnStatement;
import io.github.bananalang.parse.ast.StatementList;
import io.github.bananalang.parse.ast.StatementNode;
import io.github.bananalang.parse.ast.StringExpression;
import io.github.bananalang.parse.ast.VariableDeclarationStatement;
import io.github.bananalang.parse.ast.VariableDeclarationStatement.VariableDeclaration;
import io.github.bananalang.parse.token.Token;
import io.github.bananalang.typecheck.EvaluatedType;
import io.github.bananalang.typecheck.GlobalVariable;
import io.github.bananalang.typecheck.LocalVariable;
import io.github.bananalang.typecheck.MethodCall;
import io.github.bananalang.typecheck.Modifier2;
import io.github.bananalang.typecheck.ScriptMethod;
import io.github.bananalang.typecheck.Typechecker;
import io.github.bananalang.typecheck.MethodCall.CallType;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtMethod;
import javassist.LoaderClassPath;
import javassist.Modifier;
import javassist.bytecode.Descriptor;

public final class BananaCompiler {
    private static final String EXTENSION_METHOD_ANNOTATION = "Lbanana/internal/annotation/ExtensionMethod;";
    private static final String NULLABLE_ANNOTATION = "Lbanana/internal/annotation/Nullable;";
    private static final String NONNULL_ANNOTATION = "Lbanana/internal/annotation/NonNull;";

    private final Typechecker types;
    private final StatementList root;
    private final CompileOptions options;
    @SuppressWarnings("unused") // For now
    private final ProblemCollector problemCollector;
    private String jvmName;
    private ClassWriter result;

    private final Deque<Map.Entry<StatementList, CompileScope>> scopes = new ArrayDeque<>();
    private final Map<String, Object> lazyConstants = new HashMap<>();
    private int currentLineNumber;
    private int currentVariableDecl;

    private BananaCompiler(Typechecker types, StatementList root, CompileOptions options, ProblemCollector problemCollector) {
        this.types = types;
        this.root = root;
        this.options = options;
        this.problemCollector = problemCollector;
        this.result = null;
    }

    public static ClassWriter compileFile(File file, CompileOptions options, ProblemCollector problemCollector) throws IOException {
        try (FileReader reader = new FileReader(file)) {
            return compile(reader, options, problemCollector);
        }
    }

    public static ClassWriter compileFile(String fileName, CompileOptions options, ProblemCollector problemCollector) throws IOException {
        try (FileReader reader = new FileReader(fileName)) {
            return compile(reader, options, problemCollector);
        }
    }

    public static ClassWriter compile(Reader inputReader, CompileOptions options, ProblemCollector problemCollector) throws IOException {
        return compile(new Parser(inputReader, problemCollector), options, problemCollector);
    }

    public static ClassWriter compile(String source, CompileOptions options, ProblemCollector problemCollector) throws IOException {
        return compile(new Parser(source, problemCollector), options, problemCollector);
    }

    public static ClassWriter compile(Tokenizer tokenizer, CompileOptions options, ProblemCollector problemCollector) throws IOException {
        return compile(new Parser(tokenizer, problemCollector), options, problemCollector);
    }

    public static ClassWriter compile(List<Token> tokens, CompileOptions options, ProblemCollector problemCollector) throws IOException {
        return compile(new Parser(tokens, problemCollector), options, problemCollector);
    }

    public static ClassWriter compile(Parser parser, CompileOptions options, ProblemCollector problemCollector) throws IOException {
        StatementList root = parser.parse();
        ClassPool cp = new ClassPool(ClassPool.getDefault());
        cp.appendClassPath(new LoaderClassPath(BananaCompiler.class.getClassLoader()));
        Typechecker typechecker = new Typechecker(cp, problemCollector);
        typechecker.typecheck(root);
        return compile(typechecker, root, options, problemCollector);
    }

    public static ClassWriter compile(Typechecker types, StatementList ast, CompileOptions options, ProblemCollector problemCollector) {
        BananaCompiler compiler = new BananaCompiler(types, ast, options, problemCollector);
        try {
            return compiler.compile();
        } catch (IllegalArgumentException e) {
            problemCollector.error(e.getMessage());
            throw new GenericCompilationFailureException(problemCollector);
        }
    }

    private ClassWriter compile() {
        if (result == null) {
            double startTime = System.nanoTime();
            if (JavaBananaConstants.DEBUG) {
                System.out.println("Beginning compile of 0x" + Integer.toHexString(System.identityHashCode(root)));
            }
            result = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            jvmName = Descriptor.toJvmName(options.className());
            result.visit(options.jvmTarget(), Opcodes.ACC_PUBLIC, jvmName, null, "java/lang/Object", null);
            result.visitSource(options.sourceFileName(), null);
            {
                MethodVisitor mv = result.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
                mv.visitCode();
                mv.visitVarInsn(Opcodes.ALOAD, 0);
                mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
                mv.visitInsn(Opcodes.RETURN);
                mv.visitMaxs(-1, -1);
                mv.visitEnd();
            }
            boolean isModule = false;
            for (StatementNode child : root.children) {
                if (child instanceof FunctionDefinitionStatement) {
                    FunctionDefinitionStatement functionDefinition = (FunctionDefinitionStatement)child;
                    ScriptMethod methodDefinition = types.getMethodDefinition(functionDefinition);
                    StringBuilder descriptor = new StringBuilder("(");
                    for (EvaluatedType arg : methodDefinition.getArgTypes()) {
                        descriptor.append(arg.getDescriptor());
                    }
                    descriptor.append(')').append(methodDefinition.getReturnType().getDescriptor());
                    int access = functionDefinition.modifiers.contains(Modifier2.PUBLIC)
                        ? Opcodes.ACC_PUBLIC
                        : Opcodes.ACC_PRIVATE;
                    if (access != Opcodes.ACC_PRIVATE) {
                        isModule = true;
                    }
                    MethodVisitor mv = result.visitMethod(
                        access | Opcodes.ACC_STATIC,
                        functionDefinition.name,
                        descriptor.toString(),
                        null,
                        null
                    );
                    if (methodDefinition.getModifiers().contains(Modifier2.EXTENSION)) {
                        mv.visitAnnotation(
                            EXTENSION_METHOD_ANNOTATION,
                            false
                        );
                    }
                    if (!methodDefinition.getReturnType().getName().equals("void")) {
                        mv.visitAnnotation(
                            methodDefinition.getReturnType().isNullable()
                                ? NULLABLE_ANNOTATION
                                : NONNULL_ANNOTATION,
                            false
                        );
                    }
                    currentVariableDecl = 0;
                    for (int i = 0; i < functionDefinition.args.length; i++) {
                        VariableDeclaration arg = functionDefinition.args[i];
                        if (arg.value != null) {
                            throw new IllegalArgumentException("Default parameters not supported yet");
                        }
                        EvaluatedType type = methodDefinition.getArgTypes()[i];
                        if (arg.name == null) {
                            mv.visitParameter("this", Opcodes.ACC_FINAL);
                        } else {
                            mv.visitParameter(arg.name, 0);
                        }
                        mv.visitParameterAnnotation(
                            i,
                            type.isNullable() ? NULLABLE_ANNOTATION : NONNULL_ANNOTATION,
                            false
                        );
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
                } else if (child instanceof VariableDeclarationStatement) {
                    VariableDeclarationStatement declStmt = (VariableDeclarationStatement)child;
                    if (!declStmt.isGlobalVariableDef()) continue;
                    if (declStmt.modifiers.contains(Modifier2.LAZY)) {
                        for (VariableDeclaration decl : declStmt.declarations) {
                            Object simpleConstant = toSimpleConstant(decl.value);
                            if (simpleConstant != null) {
                                lazyConstants.put(decl.name, simpleConstant);
                                continue;
                            }
                            GlobalVariable global = types.getGlobalVariable(decl.name);
                            result.visitField(
                                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                decl.name + "$value",
                                global.getType().getDescriptor(),
                                null,
                                null
                            );
                            boolean needsExtraField = global.getType().isNullable() || global.getType().getJavassist().isPrimitive();
                            if (needsExtraField) {
                                result.visitField(
                                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                    decl.name + "$initialized",
                                    "Z",
                                    null,
                                    false
                                );
                            }
                            InstructionAdapter getMethod = new InstructionAdapter(result.visitMethod(
                                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                decl.name + "$get",
                                "()" + global.getType().getDescriptor(),
                                null,
                                null
                            ));
                            getMethod.visitCode();
                            Label startLabel = new Label();
                            getMethod.visitLabel(startLabel);
                            getMethod.visitLineNumber(declStmt.row, startLabel);
                            Label inittedLabel = new Label();
                            if (needsExtraField) {
                                getMethod.getstatic(
                                    jvmName,
                                    decl.name + "$initialized",
                                    "Z"
                                );
                                getMethod.ifne(inittedLabel);
                            } else {
                                getMethod.getstatic(
                                    jvmName,
                                    decl.name + "$value",
                                    global.getType().getDescriptor()
                                );
                                getMethod.ifnonnull(inittedLabel);
                            }
                            compileExpression(getMethod, decl.value);
                            getMethod.putstatic(
                                jvmName,
                                decl.name + "$value",
                                global.getType().getDescriptor()
                            );
                            if (needsExtraField) {
                                getMethod.iconst(1);
                                getMethod.putstatic(
                                    jvmName,
                                    decl.name + "$initialized",
                                    "Z"
                                );
                            }
                            getMethod.visitLabel(inittedLabel);
                            getMethod.getstatic(
                                jvmName,
                                decl.name + "$value",
                                global.getType().getDescriptor()
                            );
                            getMethod.visitInsn(Opcodes.ARETURN);
                            getMethod.visitMaxs(-1, -1);
                            getMethod.visitEnd();
                        }
                    } else {
                        int access = declStmt.modifiers.contains(Modifier2.PUBLIC)
                            ? Opcodes.ACC_PUBLIC
                            : Opcodes.ACC_PRIVATE;
                        if (access != Opcodes.ACC_PRIVATE) {
                            isModule = true;
                        }
                        for (VariableDeclaration decl : declStmt.declarations) {
                            GlobalVariable global = types.getGlobalVariable(decl.name);
                            FieldVisitor fv = result.visitField(
                                access | Opcodes.ACC_STATIC,
                                decl.name,
                                global.getType().getDescriptor(),
                                null,
                                null
                            );
                            fv.visitAnnotation(
                                NULLABLE_ANNOTATION,
                                false
                            );
                            fv.visitEnd();
                        }
                    }
                }
            }
            if (isModule) {
                AnnotationVisitor av = result.visitAnnotation("Lbanana/internal/annotation/BananaModule;", false);
                av.visitEnd();
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
            if (JavaBananaConstants.DEBUG) {
                System.out.println("Finished compile in " + (System.nanoTime() - startTime) / 1_000_000D + "ms");
            }
        }
        return result;
    }

    private Object toSimpleConstant(ExpressionNode expr) {
        if (expr instanceof StringExpression) {
            return ((StringExpression)expr).value;
        }
        return null;
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
        scopes.addLast(new SimpleImmutableEntry<>(node, new CompileScope(currentVariableDecl)));
        CompileScope scope = scopes.getLast().getValue();
        method.visitLabel(scope.getStartLabel());
        if (args != null) {
            Map<String, LocalVariable> localVarScope = types.getScope(node).getVars();
            for (int i = 0; i < args.length; i++) {
                addLocal(args[i].name, i);
                scope.getVarStarts().put(localVarScope.get(args[i].name), scope.getStartLabel());
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
        Map.Entry<StatementList, CompileScope> scope = scopes.removeLast();
        currentVariableDecl = scope.getValue().getFirstLocal();
        Label endLabel = new Label();
        method.visitLabel(endLabel);
        for (Map.Entry<String, LocalVariable> variable : types.getScope(scope.getKey()).getVars().entrySet()) {
            method.visitLocalVariable(
                variable.getKey() != null ? variable.getKey() : "this",
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
            if (handler.getCallType() == CallType.EXTENSION) {
                throw new IllegalArgumentException(
                    "truthy() and isEmpty() operator overloads not supported by extension methods yet"
                );
            }
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
        boolean isGlobal = stmt.isGlobalVariableDef();
        boolean isLazy = isGlobal && stmt.modifiers.contains(Modifier2.LAZY);
        for (VariableDeclaration decl : stmt.declarations) {
            if (isGlobal) {
                if (decl.value != null && !isLazy) {
                    GlobalVariable global = types.getGlobalVariable(decl.name);
                    compileExpression(method, decl.value);
                    lineNumber(stmt.row, method);
                    method.putstatic(
                        jvmName,
                        decl.name,
                        global.getType().getDescriptor()
                    );
                }
            } else {
                addLocal(decl.name, currentVariableDecl);
                Map.Entry<StatementList, CompileScope> scope = scopes.getLast();
                scope.getValue().getVarStarts().put(types.getScope(scope.getKey()).getVars().get(decl.name), label);
                if (decl.value != null) {
                    compileExpression(method, decl.value);
                    lineNumber(stmt.row, method);
                    method.visitVarInsn(Opcodes.ASTORE, currentVariableDecl);
                }
                currentVariableDecl++;
            }
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
        } else if (expr instanceof ReservedIdentifierExpression) {
            ReservedIdentifierExpression reservedExpr = (ReservedIdentifierExpression)expr;
            lineNumber(expr.row, method);
            switch (reservedExpr.identifier) {
                case NULL:
                    method.aconst(null);
                    break;
                case THIS: {
                    method.visitVarInsn(Opcodes.ALOAD, findLocal(null));
                    break;
                }
            }
        } else if (expr instanceof CallExpression) {
            CallExpression callExpr = (CallExpression)expr;
            MethodCall methodToCall = types.getMethodCall(callExpr);
            boolean isInterface;
            int opcode;
            String ownerName, descriptor = methodToCall.getDescriptor();
            Label safeNavigationLabel = null;
            if (methodToCall.isScriptMethod()) {
                if (methodToCall.getCallType() == CallType.EXTENSION) {
                    AccessExpression accessExpr = (AccessExpression)callExpr.target;
                    compileExpression(method, accessExpr.target);
                    if (accessExpr.safeNavigation) {
                        safeNavigationLabel = new Label();
                        method.dup();
                        method.ifnull(safeNavigationLabel);
                    }
                }
                for (ExpressionNode arg : callExpr.args) {
                    compileExpression(method, arg);
                }
                isInterface = false;
                opcode = Opcodes.INVOKESTATIC;
                ownerName = jvmName;
            } else {
                CtMethod javaMethod = methodToCall.getJavaMethod();
                boolean isStatic = Modifier.isStatic(javaMethod.getModifiers());
                if (
                    callExpr.target instanceof AccessExpression &&
                    (
                        methodToCall.getCallType() == CallType.INSTANCE ||
                        methodToCall.getCallType() == CallType.EXTENSION
                    )
                ) {
                    AccessExpression accessExpr = (AccessExpression)callExpr.target;
                    compileExpression(method, accessExpr.target);
                    if (accessExpr.safeNavigation) {
                        safeNavigationLabel = new Label();
                        method.dup();
                        method.ifnull(safeNavigationLabel);
                    }
                }
                if (methodToCall.getCallType() == CallType.FUNCTIONAL) {
                    compileExpression(method, callExpr.target);
                }
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
                isInterface = javaMethod.getDeclaringClass().isInterface();
                opcode = isStatic
                    ? Opcodes.INVOKESTATIC
                    : (isInterface
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
                isInterface
            );
            if (safeNavigationLabel != null) {
                method.visitLabel(safeNavigationLabel);
            }
        } else if (expr instanceof IdentifierExpression) {
            IdentifierExpression identExpr = (IdentifierExpression)expr;
            lineNumber(expr.row, method);
            int local = findLocal(identExpr.identifier);
            if (local != -1) {
                method.visitVarInsn(Opcodes.ALOAD, local);
            } else {
                GlobalVariable global = types.getGlobalVariable(identExpr.identifier);
                if (global != null) {
                    if (global.getModifiers().contains(Modifier2.LAZY)) {
                        Object simpleConstant = lazyConstants.get(identExpr.identifier);
                        if (simpleConstant != null) {
                            method.visitLdcInsn(lazyConstants.get(identExpr.identifier));
                        } else {
                            method.invokestatic(
                                jvmName,
                                identExpr.identifier + "$get",
                                "()" + global.getType().getDescriptor(),
                                false
                            );
                        }
                    } else {
                        method.getstatic(
                            jvmName,
                            global.getName(),
                            global.getType().getDescriptor()
                        );
                    }
                } else {
                    CtField field = types.getFieldAccess(identExpr);
                    if (field == null) {
                        throw new AssertionError("Missing IdentifierExpression type data\n" + identExpr);
                    }
                    method.getstatic(
                        Descriptor.toJvmName(field.getDeclaringClass()),
                        field.getName(),
                        field.getSignature()
                    );
                }
            }
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
                case BITWISE_OR:
                case BITWISE_XOR:
                case BITWISE_AND:
                case LEFT_SHIFT:
                case RIGHT_SHIFT:
                case ADD:
                case SUBTRACT:
                case MULTIPLY:
                case DIVIDE:
                case MODULUS: {
                    MethodCall methodCall = types.getMethodCall(binExpr);
                    boolean isInterface;
                    int opcode;
                    String ownerName, descriptor = methodCall.getDescriptor();
                    if (methodCall.isScriptMethod()) {
                        compileExpression(method, binExpr.left);
                        compileExpression(method, binExpr.right);
                        isInterface = false;
                        opcode = Opcodes.INVOKESTATIC;
                        ownerName = jvmName;
                    } else {
                        CtMethod javaMethod = methodCall.getJavaMethod();
                        boolean isStatic = Modifier.isStatic(javaMethod.getModifiers());
                        if (Modifier.isVarArgs(javaMethod.getModifiers())) {
                            int actualArgCount = Descriptor.numOfParameters(descriptor);
                            int endParen = descriptor.indexOf(')');
                            String arrType = descriptor.substring(descriptor.lastIndexOf('L', endParen - 2) + 1, endParen - 1);
                            if (actualArgCount == 1) {
                                method.iconst(2);
                                method.visitTypeInsn(Opcodes.ANEWARRAY, arrType);
                                method.dup();
                                method.iconst(0);
                                compileExpression(method, binExpr.left);
                                method.visitInsn(Opcodes.AASTORE);
                                method.dup();
                                method.iconst(1);
                                compileExpression(method, binExpr.right);
                                method.visitInsn(Opcodes.AASTORE);
                            } else if (actualArgCount == 2) {
                                compileExpression(method, binExpr.left);
                                method.iconst(1);
                                method.visitTypeInsn(Opcodes.ANEWARRAY, arrType);
                                method.dup();
                                method.iconst(1);
                                compileExpression(method, binExpr.right);
                                method.visitInsn(Opcodes.AASTORE);
                            } else {
                                throw new AssertionError(actualArgCount);
                            }
                        } else {
                            compileExpression(method, binExpr.left);
                            compileExpression(method, binExpr.right);
                        }
                        isInterface = javaMethod.getDeclaringClass().isInterface();
                        opcode = isStatic
                            ? Opcodes.INVOKESTATIC
                            : (isInterface
                                ? Opcodes.INVOKEINTERFACE
                                : Opcodes.INVOKEVIRTUAL);
                        ownerName = Descriptor.toJvmName(javaMethod.getDeclaringClass());
                    }
                    lineNumber(expr.row, method);
                    method.visitMethodInsn(
                        opcode,
                        ownerName,
                        methodCall.getName(),
                        descriptor,
                        isInterface
                    );
                    break;
                }
                default:
                    throw new AssertionError(binExpr.type);
            }
        } else if (expr instanceof CastExpression) {
            CastExpression castExpr = (CastExpression)expr;
            compileExpression(method, castExpr.target);
            EvaluatedType destType = types.getType(castExpr);
            method.visitTypeInsn(Opcodes.CHECKCAST, destType.getJvmName());
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
            String identifier = ((IdentifierExpression)expr.target).identifier;
            int local = findLocal(identifier);
            if (local != -1) {
                method.visitVarInsn(Opcodes.ASTORE, local);
            } else {
                GlobalVariable global = types.getGlobalVariable(identifier);
                if (global.getModifiers().contains(Modifier2.LAZY)) {
                    throw new AssertionError(expr);
                } else {
                    method.putstatic(
                        jvmName,
                        global.getName(),
                        global.getType().getDescriptor()
                    );
                }
            }
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
        Iterator<Map.Entry<StatementList, CompileScope>> iterator = scopes.descendingIterator();
        while (iterator.hasNext()) {
            CompileScope scope = iterator.next().getValue();
            Integer local = scope.getLocals().get(name);
            if (local != null) {
                return local;
            }
        }
        return -1;
    }

    private void lineNumber(int line, InstructionAdapter method) {
        if (line != currentLineNumber) {
            currentLineNumber = line;
            Label lineNumberLabel = new Label();
            method.visitLabel(lineNumberLabel);
            method.visitLineNumber(line, lineNumberLabel);
        }
    }
}
