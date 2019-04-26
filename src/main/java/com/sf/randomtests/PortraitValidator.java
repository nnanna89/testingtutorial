package com.sf.randomtests;

import com.sf.validation.v3.aware.PrefaceImageValidator;
import com.sf.validation.v3.vo.FaceData;
import com.sf.validation.v3.vo.MetricData;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

/**
 * @author lash
 */
public class PortraitValidator {
    private static final String JPG_FILE_EXT = ".jpeg";
    private static final String NEW_LINE = "\n";
    private static final String THRESHOLD_FILE_DIR = "data_dictionary.xml";
    private static double faceDetectionMin = 0.1, faceDetectionMax = 0.9, granularity = 0.2, sensitivity = 0.7;

    public static void main(String[] args) throws IOException {
        if(args == null){
            System.out.println("Please specify a folder where the images are located");
            return;
        }

        //validate the file directory
        File imageFileDir = new File(args[0]);
        if(!imageFileDir.exists()){
            System.out.println("Specified image directory does not exist");
            return;
        }

        if(!imageFileDir.isDirectory()){
            System.out.println("Specified directory is not a folder");
            return;
        }

        //get the threshold file
        File thresholdFile = new File(THRESHOLD_FILE_DIR);
        if(!thresholdFile.exists() || !thresholdFile.isFile()){
            System.out.println("Invalid directory for threshold file");
            return;
        }

        //set the dlls in system props
        String customPath = null;
        if(args.length > 1){
            customPath = args[1];
        }else{
            customPath = System.getProperty("user.dir");
        }
        System.out.println("Derived custom directory: " + customPath);

        System.setProperty("com.aware.preface.PrefaceJNI.libPath", customPath + "\\aw_preface.dll");
        System.setProperty("com.aware.preface.PrefaceJNI.jniLibPath", customPath + "\\aw_preface_jni.dll");


        //iterate through the images
        for(File imageFile : imageFileDir.listFiles()){
            //validate the image
            PrefaceImageValidator imageValidator = new PrefaceImageValidator(false); //false means don't use their classifier file
            if(imageFile.getName().endsWith(JPG_FILE_EXT)){
                System.out.println(imageFile.getName() + NEW_LINE);
                System.out.println("===============================");

                FaceData data = imageValidator.validate(FileUtils.readFileToByteArray(imageFile), FileUtils.readFileToByteArray(thresholdFile),
                        faceDetectionMin, faceDetectionMax, granularity, sensitivity);

                //print results
                if(data != null){
                    for(MetricData md : data.getMetrics()){
                        String status = md.metricCompliant.equals("OK") ? "PASSED": "FAILED";
                        System.out.println("Metric: " + md.metric + " | Value: " + md.metricValue + " | Status: " + status + NEW_LINE);
                    }

                    System.out.println(imageFile.getName() + NEW_LINE + NEW_LINE);
                }
            }
        }
    }
}
