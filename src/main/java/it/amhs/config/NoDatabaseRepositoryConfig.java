package it.amhs.config;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.amhs.repository.AMHSChannelRepository;
import it.amhs.repository.AMHSDeliveryReportRepository;
import it.amhs.repository.AMHSMessageRepository;

@Configuration
@ConditionalOnProperty(name = "amhs.database.enabled", havingValue = "false")
public class NoDatabaseRepositoryConfig {

    @Bean
    AMHSMessageRepository amhsMessageRepositoryNoOp() {
        return createNoOpRepository(AMHSMessageRepository.class, Map.of());
    }

    @Bean
    AMHSDeliveryReportRepository amhsDeliveryReportRepositoryNoOp() {
        return createNoOpRepository(AMHSDeliveryReportRepository.class, Map.of());
    }

    @Bean
    AMHSChannelRepository amhsChannelRepositoryNoOp() {
        return createNoOpRepository(AMHSChannelRepository.class, Map.of());
    }

    @SuppressWarnings("unchecked")
    private static <T> T createNoOpRepository(Class<T> repositoryType, Map<String, Object> fixedResults) {
        InvocationHandler handler = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) {
                String methodName = method.getName();
                if ("toString".equals(methodName)) {
                    return repositoryType.getSimpleName() + "NoOpProxy";
                }
                if ("hashCode".equals(methodName)) {
                    return System.identityHashCode(proxy);
                }
                if ("equals".equals(methodName)) {
                    return proxy == args[0];
                }

                if (fixedResults.containsKey(methodName)) {
                    return fixedResults.get(methodName);
                }

                Class<?> returnType = method.getReturnType();
                if (returnType.equals(Void.TYPE)) {
                    return null;
                }
                if (returnType.equals(boolean.class)) {
                    return false;
                }
                if (returnType.equals(long.class) || returnType.equals(int.class) || returnType.equals(short.class) || returnType.equals(byte.class)) {
                    return 0;
                }
                if (returnType.equals(double.class) || returnType.equals(float.class)) {
                    return 0.0;
                }
                if (Optional.class.isAssignableFrom(returnType)) {
                    return Optional.empty();
                }
                if (List.class.isAssignableFrom(returnType)) {
                    return Collections.emptyList();
                }
                if (Iterable.class.isAssignableFrom(returnType)) {
                    return Collections.emptyList();
                }
                if (methodName.startsWith("save") && args != null && args.length > 0) {
                    return args[0];
                }
                return null;
            }
        };

        return (T) Proxy.newProxyInstance(
            repositoryType.getClassLoader(),
            new Class<?>[] { repositoryType },
            handler
        );
    }
}
