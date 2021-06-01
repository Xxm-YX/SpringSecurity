package com.example.SpringSecurityDemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Bean
//    PasswordEncoder passwordEncoder(){
//        DelegatingPasswordEncoder delegatingPasswordEncoder =
//                (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        //设置defaultPasswordEncoderForMatches为NoOpPasswordEncoder
//        delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NoOpPasswordEncoder.getInstance());
//        return delegatingPasswordEncoder;
//    }

    @Bean
    //不加密
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication() //开启在内存中定义用户
                .withUser("zyx")//用户名
                .password("456")//密码
                .roles("admin"); //角色

        //配置用户用and进行连接。
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //忽略的URL地址，一些静态文件
        web.ignoring().antMatchers(
                "/js/**",
                "/css/**",
                "/images/**"
        );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()//表示结束当前标签，上下文回到HttpSecurity，开启新一轮的配置。
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
                .permitAll()//表示登录相关的页面/接口不要被拦截。
                .usernameParameter("name")
                .passwordParameter("passwd")
//                .defaultSuccessUrl("/index")  如果访问的是hello，登录成功后，会继续访问hello
//                .successForwardUrl("/index")   如果访问的是hello，登录成功后会，去访问index
//                .failureForwardUrl()   登录失败  发生服务器跳转
//                .failureUrl()          登录失败，发生重定向
                .and()
                .logout()//GET请求
                .logoutUrl("/logout")//修改默认注销URL
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST")) //修改注销URL，还可以修改请求方式
                .logoutSuccessUrl("/index")//登录成功要跳转的页面
                .deleteCookies()//清除cookie
                .clearAuthentication(true)//清除认证信息
                .invalidateHttpSession(true)//使HttpSession失效  默认就会清除
                .permitAll()//绕开过滤器
                .and()
                .csrf().disable();
    }
}
