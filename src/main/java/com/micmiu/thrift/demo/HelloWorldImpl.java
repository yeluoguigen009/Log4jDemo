package com.micmiu.thrift.demo;

import org.apache.thrift.TException;

/**
 * blog http://www.micmiu.com
 *
 * @author Michael
 *
 */
public class HelloWorldImpl implements HelloWorldService.Iface {

	public HelloWorldImpl() {
	}

	@Override
	public String sayHello(String username) throws TException {
		System.out.println("Server processed " + username);
		return "Hi," + username + " welcome to my blog www.micmiu.com\n";
	}

}