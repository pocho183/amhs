package it.amhs.protocol;

import it.amhs.mta.MTAService;

public class ROSEService {

 public void process(byte[] data){

  int op = decodeOperation(data);

  if(op==1){

   new MTAService()
    .transfer(data);

  }

 }

 private int decodeOperation(byte[] d){

  return d[0];

 }

}