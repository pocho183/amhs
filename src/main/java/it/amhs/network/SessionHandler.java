package it.amhs.network;

import java.io.InputStream;

import it.amhs.protocol.ACSEService;

import javax.net.ssl.SSLSocket;

public class SessionHandler implements Runnable {

 private final SSLSocket socket;

 public SessionHandler(SSLSocket s){

  this.socket = s;

 }

 public void run(){

  try{

   InputStream in =
    socket.getInputStream();

   byte[] buffer =
    new byte[8192];

   int len =
    in.read(buffer);

   ACSEService acse =
    new ACSEService();

   acse.handle(buffer);

  }
  catch(Exception ex){

   ex.printStackTrace();

  }

 }

}