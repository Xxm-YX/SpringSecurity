package com.example.SpringSecurityDemo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.code.kaptcha.Producer;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;
import javax.xml.crypto.Data;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Properties;

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

    @Autowired
    public DataSource dataSource;

//    @Bean
//    public JdbcTokenRepositoryImpl jdbcTokenRepository(){
//        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
//        jdbcTokenRepository.setDataSource(dataSource);
//        return jdbcTokenRepository;
//    }

    @Bean
    //不加密
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    MyAuthenticationProvider myAuthenticationProvider(){
        MyAuthenticationProvider myAuthenticationProvider = new MyAuthenticationProvider();
        myAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        myAuthenticationProvider.setUserDetailsService(userDetailsService());
        return myAuthenticationProvider;
    }


    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        ProviderManager manager = new ProviderManager(Arrays.asList(myAuthenticationProvider()));
        return manager;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication() //开启在内存中定义用户
                .withUser("zyx")//用户名
                .password("123")//密码
                .roles("admin") //角色
                .and()
                .withUser("xxm")
                .password("123")
                .roles("user");

        //配置用户用and进行连接。
    }

    @Override
    protected UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("zyx").password("123").roles("admin").build());
        manager.createUser(User.withUsername("xxm").password("123").roles("user").build());
        return manager;
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

    /**
     * 角色继承
     * @return
     */
    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return hierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()//基于URL的限制访问开启

                .antMatchers("/rememberme/**").rememberMe()//需要rememberMe才能进行访问
                .antMatchers("/admin/**").fullyAuthenticated()//  fullAuthenticated 不包含rememberMe的验证，authenticated包含rememberMe的验证
//                .antMatchers("/admin/**").hasRole("admin")//配置访问路径，那些
//                .antMatchers("/user/**").hasRole("user")
                .antMatchers("/vc.jpg").permitAll()
                .anyRequest().authenticated()////映射所有请求  并进行验证
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
                .successHandler((req,resp,authentication) ->{ //登录成功的回调函数，
                    //这里传进来的是一个AuthenticationSuccessHandler 对象
                    //AuthenticationSuccessHandler 是个接口
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(new ObjectMapper().writeValueAsString(principal));
                    out.flush();
                    out.close();
                })
                .failureHandler((req,resp,e) ->{
                  resp.setContentType("application/json;charset=utf-8");
                  PrintWriter out = resp.getWriter();
                  out.write(e.getMessage());
                  out.flush();
                  out.close();
                })
                .and()
                .logout()//GET请求
                .logoutUrl("/logout")//修改默认注销URL
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST")) //修改注销URL，还可以修改请求方式
                .logoutSuccessHandler((req,resp,authentication) -> { // 成功后的回调函数，发送注销信息
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    resp.setStatus(200);
                    out.write("注销成功");
                    out.flush();
                    out.close();
                })
//                .logoutSuccessUrl("/index")//登录成功要跳转的页面
                .deleteCookies()//清除cookie
                .clearAuthentication(true)//清除认证信息
                .invalidateHttpSession(true)//使HttpSession失效  默认就会清除
                .permitAll()//绕开过滤器
                .and()
                .rememberMe()//记住我，配置这个就行
                .key("zyx") //这个key原本是系统设置的UUID,但是服务端重启的话会变。
//                .tokenRepository(jdbcTokenRepository())// 自带的数据库模型，里面有对token表的操作
                .and()
                .csrf().disable()
                .sessionManagement().maximumSessions(1)//设置会话数量为1
//                .exceptionHandling()
//                .authenticationEntryPoint((req, resp, e) -> {
//                    resp.setContentType("application/json;charset=utf-8");
//                    PrintWriter out = resp.getWriter();
//                    resp.setStatus(403);
//                    out.append("{\"code\":1,\"msg\":\"登录失败,请重新登录!\",\"data\":\"failed\"}");
////                    out.write("尚未登录，请先登录");
//                    out.flush();
//                    out.close();
//                });
        ;
    }


    @Bean
    Producer verifyCode() {
        Properties properties = new Properties();
        properties.setProperty("kaptcha.image.width", "150");
        properties.setProperty("kaptcha.image.height", "50");
        properties.setProperty("kaptcha.textproducer.char.string", "0123456789");
        properties.setProperty("kaptcha.textproducer.char.length", "4");
        Config config = new Config(properties);
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
        defaultKaptcha.setConfig(config);
        return defaultKaptcha;
    }
}
