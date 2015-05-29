package net.floodlightcontroller.pktinhistory;
//import package com.impetus.doc.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Utility class to scan files using ClamAV antivirus APIs.
 *
 * @author ncverma
 *
 */


import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.taldius.clamav.ClamAVScanner;
import net.taldius.clamav.ClamAVScannerFactory;

/**
 * Utility class to scan files using ClamAV antivirus APIs.
 *
 * @author ncverma
 *
 */
public class ClamAVUtil extends Thread{
    protected static Logger logger= LoggerFactory.getLogger(ClamAVUtil.class);

       // Host where 'clamd' process is running
       private String clamdHost;
      
       // Port on which 'clamd' process is listening
       private String clamdPort;
      
       // Connection time out to connect 'clamd' process
       private String connTimeOut;
      
       private ClamAVScanner scanner;
      
       public void setClamdHost(String clamdHost){
              this.clamdHost = clamdHost;
       }
      
       public String getClamdHost(){
              return this.clamdHost;
       }
      
       public void setClamdPort(String clamdPort){
              this.clamdPort = clamdPort;
       }
      
       public String getClamdPort(){
              return this.clamdPort;
       }
      
       public void setConnTimeOut(String connTimeOut){
              this.connTimeOut = connTimeOut;
       }
      
       public String getConnTimeOut(){
              return this.connTimeOut;
       }
      
       /**
        * Method to initialize clamAV scanner
        */
       public void initScanner(){
             
              ClamAVScannerFactory.setClamdHost(clamdHost);

              ClamAVScannerFactory.setClamdPort(Integer.parseInt(clamdPort));

              int connectionTimeOut = Integer.parseInt(connTimeOut);
             
              if (connectionTimeOut > 0) {
                     ClamAVScannerFactory.setConnectionTimeout(connectionTimeOut);
              }
              this.scanner = ClamAVScannerFactory.getScanner();
       }

       public ClamAVScanner getClamAVScanner() {
              return scanner;
       }

       /**
        * Method scans files to check whether file is virus infected
        *
        * @param destFilePath file path
        * @return
        * @throws Exception
        */
       public boolean fileScanner(String destFilePath) throws Exception  {

              return fileScanner(new FileInputStream(destFilePath));
       }

       /**
        * Method scans files to check whether file is virus infected
        *
        * @param fileInputStream
        * @return
        * @throws Exception
        */
       public boolean fileScanner(InputStream fileInputStream) throws Exception {

              boolean resScan = false;

              if (fileInputStream != null) {

                     resScan = scanner.performScan(fileInputStream);

              } else {

                     throw new Exception();
              }
              return resScan;
       }

       @Override
   	public void run() {

       setClamdHost("127.0.0.1");
   	   setClamdPort("3310");
   	   setConnTimeOut("3600");
   	   initScanner();
   	 
   	   boolean result = false;
	try {
		
		result = fileScanner("/home/osboxes/Downloads/eicar.com");
		logger.info(scanner.getMessage());
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
   	   
   	   if(!result)
   	   logger.info("this file is infected");
   	   else
   	   logger.info("this file is not infected");

}
}
	                                           