//package com.example.SpringSecurityDemo.config;
//
//import com.example.SpringSecurityDemo.service.UserDetailsService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
///**
// * Spring Security配置类
// */
//@EnableWebSecurity
//public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//
//    @Autowired
//    private UserDetailsService userDetailsServiceImpl;
//
//    /**
//     * 用户配置类
//     * @param auth
//     * @throws Exception
//     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        /**
//         * 指定用户认证时，默认从哪获取认证用户信息
//         */
//        auth.userDetailsService(userDetailsServiceImpl);
//    }
//
//    /**
//     * Http安全配置
//     * @param http
//     * @throws Exception
//     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        /**
//         * 表单登录：使用默认二点表单登录页面和登录端点/login进行登录
//         * 退出登录：使用默认的退出登录端点/logout退出登录
//         * 记住我：使用默认的“记住我”功能，把记住用户以登录的Token存在内存里，记30分钟
//         * 权限：除了/toHome 和 /toUser之外，其他的请求都要求用户已登录
//         * 注意：Controller中也对URL配置了权限，如果WebSecurityConfig中和Controller中
//         */
//        http
//                .formLogin()
//                    .defaultSuccessUrl("/toHome",false)
//                    .permitAll()
//                    .and()
//                .logout()
//                    .permitAll()
//                    .and()
//                .rememberMe()
//                    .tokenValiditySeconds(1800)
//                    .and()
//                .authorizeRequests()
//                    .antMatchers("/toHome","toUser")
//                    .permitAll()
//                    .anyRequest()
//                    .authenticated();
//    }
//
//    /**
//     * 密码加密器
//     */
//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        /**
//         * BCryptPasswordEncoder：相同的密码明文每次生成的密文都不同，安全性更高
//         */
//        return new BCryptPasswordEncoder();
//    }
//}
