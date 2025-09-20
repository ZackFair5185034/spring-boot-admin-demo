package xyx.foxicle.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.reactive.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

import java.util.UUID;

import static io.netty.handler.codec.http.HttpMethod.DELETE;
import static io.netty.handler.codec.http.HttpMethod.POST;

@Configuration(proxyBeanMethods = false)
public class SecuritySecureConfig {

    private final AdminServerProperties adminServer;

    private final SecurityProperties security;

    public SecuritySecureConfig(AdminServerProperties adminServer, SecurityProperties security) {
        this.adminServer = adminServer;
        this.security = security;
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl(this.adminServer.path("/"));

        // 使用现代的方式配置授权规则
        http.authorizeHttpRequests(authorize -> authorize
                        // 静态资源允许访问
                        .requestMatchers(String.valueOf(PathRequest.toStaticResources().atCommonLocations())).permitAll()
                        // Admin Server 特定路径 - 使用字符串路径模式
                        .requestMatchers(
                                adminServer.path("/login"),
                                adminServer.path("/actuator/info"),
                                adminServer.path("/actuator/health")
                        ).permitAll()
                        // 任何其他请求需要认证
                        .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                        .loginPage(adminServer.path("/login"))
                        .successHandler(successHandler)
                )
                .logout(logout -> logout
                        .logoutUrl(adminServer.path("/logout"))
                )
                .httpBasic(Customizer.withDefaults()); // 允许 Client 注册

        // 配置 CSRF
        http.csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                // 忽略特定端点的 CSRF 保护 - 使用字符串路径模式和方法
                .ignoringRequestMatchers(
                        request -> {
                            String path = request.getServletPath();
                            String method = request.getMethod();
                            // 忽略 /instances 的 POST 请求
                            if (path != null && path.equals(adminServer.path("/instances")) && POST.name().equals(method)) {
                                return true;
                            }
                            // 忽略 /instances/* 的 DELETE 请求
                            if (path != null && path.startsWith(adminServer.path("/instances/")) && DELETE.name().equals(method)) {
                                return true;
                            }
                            // 忽略所有 actuator 端点
                            if (path != null && path.startsWith(adminServer.path("/actuator/"))) {
                                return true;
                            }
                            return false;
                        }
                )
        );

        http.rememberMe((rememberMe) -> rememberMe.key(UUID.randomUUID().toString()).tokenValiditySeconds(1209600));

        return http.build();

    }

    // Required to provide UserDetailsService for "remember functionality"
    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.withUsername(security.getUser().getName())
                .password(passwordEncoder.encode(security.getUser().getPassword()))
                .roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}