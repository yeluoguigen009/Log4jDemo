package com.evan.maventest;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

/**
 * Hello world!
 *
 */
public class App 
{

    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
        //BasicConfigurator.configure();

        Logger logger = Logger.getLogger(App.class);
        logger.debug("The first log4j log");

     

   
    }
}
