package ca.sheridancollege.security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private LoginAccessDeniedHandler accessDeniedHandler;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
		.antMatchers("/admin/**").hasRole("ADMIN")
		.antMatchers("/employee/**").hasAnyRole("ADMIN", "EMPLOYEE")
		.antMatchers("/", "/images/**", "/css/**", "/js/**", "/**", "/users/**").permitAll()
		.anyRequest().authenticated()
		.and().formLogin().loginPage("/login").permitAll()
		.and().logout().invalidateHttpSession(true).clearAuthentication(true).logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		.logoutSuccessUrl("/").permitAll()
		.and().exceptionHandling().accessDeniedHandler(accessDeniedHandler)
		;
	}
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.
		inMemoryAuthentication()
		.passwordEncoder(NoOpPasswordEncoder.getInstance())
		.withUser("Admin").password("password").roles("ADMIN")
		.and()
		.withUser("Employee").password("password").roles("EMPLOYEE"); 
		}
	

}
