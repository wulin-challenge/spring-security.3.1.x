package org.springframework.security.access.expression;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.core.Authentication;

/**
 * Facade which isolates Spring Security's requirements for evaluating security expressions
 * from the implementation of the underlying expression objects
 * 
 * <p> Facade将Spring Security评估安全表达式的要求与基础表达式对象的实现隔离开来
 *
 * @author Luke Taylor
 * @since 3.1
 */
public interface SecurityExpressionHandler<T> extends AopInfrastructureBean {
    /**
     * @return an expression parser for the expressions used by the implementation.
     * 
     * <p> 实现使用的表达式的表达式解析器
     */
    ExpressionParser getExpressionParser();

    /**
     * Provides an evaluation context in which to evaluate security expressions for the invocation type.
     * 
     * <p> 提供一个评估上下文，在该评估上下文中可以评估调用类型的安全性表达式。
     */
    EvaluationContext createEvaluationContext(Authentication authentication, T invocation);
}
