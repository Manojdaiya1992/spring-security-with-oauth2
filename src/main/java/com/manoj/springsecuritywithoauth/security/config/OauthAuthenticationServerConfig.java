package com.manoj.springsecuritywithoauth.security.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.servlet.HandlerInterceptor;

import com.manoj.springsecuritywithoauth.security.config.classes.CustomUserDetail;
import com.manoj.springsecuritywithoauth.security.config.classes.CustomUserDetailsService;

@Configuration
@EnableAuthorizationServer
public class OauthAuthenticationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	private AuthenticationManager authenticationManager;
	
	private CustomUserDetailsService userDetails;
	
	private String clientId="$2y$12$eUovJt3tV2DxfQEspaPxcucmYcPYPBGGojGoiI1vt4Oic3hfm62w6";
	
	private String clientSecret="$2y$12$QEK/vqmxWmO3ANBpH/5IQ.b1piR3dlk/NPn/ECvdiElK/yvOzStyq";

	private int accessTokenValiditySeconds=180;

	private int refreshTokenValiditySeconds=300;
	
	public OauthAuthenticationServerConfig(AuthenticationManager authenticationManager, CustomUserDetailsService userDetails) {
		  this.authenticationManager = authenticationManager;
		  this.userDetails = userDetails;
	}
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		//super.configure(clients);
		
		clients.inMemory().withClient(clientId).secret("{noop}"+clientSecret)
		.authorizedGrantTypes("password","refresh_token","client_credentials")
		.accessTokenValiditySeconds(accessTokenValiditySeconds)
		.refreshTokenValiditySeconds(refreshTokenValiditySeconds).scopes(new String[] {"read","write"});
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		List<TokenEnhancer> tokenEnhancerList = new ArrayList<>();
		tokenEnhancerList.add(oauthTokenEnhancer());
		tokenEnhancerList.add(tokenEnhancer());
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(tokenEnhancerList);
		
		endpoints.pathMapping("/oauth/token", "/login").addInterceptor(new HandlerInterceptor() {
			@Override
			public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
					throws Exception {
				return HandlerInterceptor.super.preHandle(request, response, handler);
			}
		})//.tokenStore(tokenStore())
		.authenticationManager(authenticationManager).userDetailsService(userDetails)
		.tokenStore(tokenStore()).accessTokenConverter(tokenEnhancer()).tokenEnhancer(tokenEnhancerChain);
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("isAuthenticated()").tokenKeyAccess("permitAll()");
	}
	
	   @Bean
	   public JwtAccessTokenConverter tokenEnhancer() {
	      JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
	      converter.setSigningKey("abc");
	      converter.setVerifierKey("abc");
	      DefaultAccessTokenConverter defaultAccessTokenConverter =  (DefaultAccessTokenConverter) converter.getAccessTokenConverter();
          defaultAccessTokenConverter.setUserTokenConverter(userAuthenticationConverter());
	      return converter;
	   }
	   
	   @Bean
	   public JwtTokenStore tokenStore() {
	      return new JwtTokenStore(tokenEnhancer());
	   }
	   
	   @Bean
	   public UserAuthenticationConverter userAuthenticationConverter() {
	       DefaultUserAuthenticationConverter defaultUserAuthenticationConverter = new DefaultUserAuthenticationConverter();
	       defaultUserAuthenticationConverter.setUserDetailsService(userDetails);
	       return defaultUserAuthenticationConverter;
	   }
	
	/*@Bean
	public TokenStore tokenStore() {
		return new InMemoryTokenStore();
	}*/
	   
	   
	   public TokenEnhancer oauthTokenEnhancer() {
	    return new TokenEnhancer() {
			@Override
			public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				  CustomUserDetail user = (CustomUserDetail) authentication.getPrincipal();
			        final Map<String, Object> additionalInfo = new HashMap<>();
			        additionalInfo.put("id", user.getPassword());
			        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
			        return accessToken;
			}
		};
	   }
	   
}
