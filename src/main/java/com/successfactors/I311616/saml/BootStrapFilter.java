package com.successfactors.I311616.saml;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

public class BootStrapFilter implements Filter {
	
	private static Logger log = LogManager.getLogger(BootStrapFilter.class);

	public void destroy() {
		
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain nextChain) throws IOException, ServletException {
		nextChain.doFilter(request, response);
	}

	public void init(FilterConfig config) throws ServletException {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			log.error("Boot strap error");
			throw new RuntimeException(e);
		}
	}

}
