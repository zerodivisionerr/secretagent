package main

import (
        "fmt"
        "encoding/json"
        "strings"
        "github.com/aws/aws-sdk-go/aws"
        "github.com/aws/aws-sdk-go/aws/session"
        "github.com/aws/aws-sdk-go/service/secretsmanager"
        admv1 "k8s.io/api/admission/v1"
        corev1 "k8s.io/api/core/v1"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
        log "github.com/sirupsen/logrus"
        "os"
        "net/http"
        "crypto/tls"
        "io/ioutil"
        "regexp"
        "time"
  )

func mutate (admissionReview *admv1.AdmissionReview) (*admv1.AdmissionReview, error) {
  var patches []JSONPatch
  pod := &corev1.Pod{} // parse pod from admission review
  if err := json.Unmarshal(admissionReview.Request.Object.Raw, pod); err != nil {
    log.Error("Could not unmarshal pod object from admission review:", err)
    return admissionReview, err
  }
  patchesRequired := false // approve Admission Review with no patches by default

  // check for ASM_STORED_SECRET_ in env vars and pull requested asm secret if found
  for i := 0; i < len(pod.Spec.Containers); i++ {
    c := pod.Spec.Containers[i]
    if len(c.Env) < 1 {
      log.Warn("Envs field appears to be empty. No changes required.")
    } else {
      for j, kvpair := range c.Env {
        env := kvpair.Name
        envNum := j
        val := kvpair.Value
        if strings.Contains(val, "ASM_STORED_SECRET_") {
          log.Info(fmt.Sprintf("Processing: %s", env))
          patchesRequired = true
          secretValue, _ := getAsmSecret(val)
          container := i
          log.Debug(fmt.Sprintf("Retrieved value from ASM: %s", secretValue))
          patch := secretToJsonPatch(secretValue, envNum, container)
          log.Debug(fmt.Sprintf("Patch is: \nOP: %s\n Path: %s\n Value: %s", patch.OP, patch.Path, patch.Value))
          patches = append(patches, patch)
          log.Debug(fmt.Sprintf("Patches array is now:\n%s", patches))
        }
      }
    }
  }

  if !patchesRequired {
    // allow admission reviews that need no changes by default
    admissionResponse := &admv1.AdmissionResponse{
      UID:       admissionReview.Request.UID,
      Allowed:   true,
    }

    admissionReviewResponse := &admv1.AdmissionReview{
        TypeMeta: metav1.TypeMeta{
        Kind:       "AdmissionReview",
        APIVersion: "admission.k8s.io/v1",
      },
    Response: admissionResponse,
    }

    return admissionReviewResponse, nil
  }


  log.Debug(fmt.Sprintf("Final patches to be applied are:\n %s", patches))

  patchBytes, _ := json.Marshal(patches) // convert patches into byte array for inclusion in admission response

  log.Debug(fmt.Sprintf("Final patches after json marshal: %s", patches))
  patchType := admv1.PatchTypeJSONPatch

  // build admission response with changeset as patchBytes included
  admissionResponse := &admv1.AdmissionResponse{
    UID:       admissionReview.Request.UID,
    Allowed:   true,
    Patch:     patchBytes,
    PatchType: &patchType,
  }

  admissionReviewResponse := &admv1.AdmissionReview{
      TypeMeta: metav1.TypeMeta{
      Kind:       "AdmissionReview",
      APIVersion: "admission.k8s.io/v1",
    },
  Response: admissionResponse,
  }

  // return admission response for processing by k8s
  return admissionReviewResponse, nil
}

func httpToAdmReview(body []byte) (*admv1.AdmissionReview, error){
  // translate json body into admissionreview type
  admissionReview := &admv1.AdmissionReview{}
  err := json.Unmarshal(body, admissionReview) // json.NewDecoder(body).Decode(admissionReview)
  if err != nil {
    log.Errorf("Could not unmarshal http body to admission review object: %s", err)
  }
  return admissionReview, err
}

type JSONPatch struct {
  OP    string          `json:"op"`
  Path  string          `json:"path"`
  Value interface{}     `json:"value,omitempty"`
}

func getAsmSecret(varInput string) (string, error) {
  var secretValue string
  inputPathKey := strings.Replace(varInput, "ASM_STORED_SECRET_", "", 1) // drop prefix marker
  splitPathKey := regexp.MustCompile("\\?").Split(inputPathKey, -1) // separate secret path from key at `?` divider
  if len(splitPathKey) != 2 {
    return "Improperly formatted environment variable value. Unable to parse.", fmt.Errorf("Failed parsing %s. Expected format of ASM_STORED_SECRET_/aws/secret/path?desiredSecretKey", varInput)
  }
  secretPath := splitPathKey[0]
  secretKey := splitPathKey[1]
  log.Debug(fmt.Sprintf("Retrieving %s from %s", secretKey, secretPath))
  sess, err := session.NewSessionWithOptions(session.Options{
          Profile: "AWS_PROFILE",
          Config: aws.Config{
              Region: aws.String("AWS_DEFAULT_REGION"),
            },
          })
  if err != nil {
    log.Errorf("Error establishig connection to aws: %v", err)
    return secretValue, err
  }

  svc := secretsmanager.New(sess)
  input := &secretsmanager.GetSecretValueInput{
      SecretId: aws.String(secretPath),
  }
  result, err := svc.GetSecretValue(input)
  if err != nil {
    log.Errorf("Failed to retrieve secret, %s, from ASM: %v", secretPath, err)
    return secretValue, err
  }
  rawSecretString := *result.SecretString
  var secretString map[string]interface{}
  json.Unmarshal([]byte(rawSecretString), &secretString)

  secretValue = secretString[secretKey].(string)
  log.Debug(fmt.Sprintf("Parsed secret as: %s", secretValue))
  return secretValue, err
}

func secretToJsonPatch(secretValue string, envNum int, container int) (JSONPatch) {
  patch := JSONPatch{
    OP: "replace",
    Path: fmt.Sprintf("/spec/containers/%d/env/%d/value", container, envNum),
    Value: secretValue,
  }
  return patch
}

func createTLSConf() (tls.Certificate) {
  tlsKeyPair, err := tls.LoadX509KeyPair("tls/server.crt", "tls/server.key")
  if err != nil {
    log.Fatalf("Unable to parse tls cert. Unable to continue... %s", err)
  }
  return tlsKeyPair
}

func safeCrash(err error, writer http.ResponseWriter) {
  log.Error(err)
  writer.WriteHeader(http.StatusInternalServerError)
  log.Error(fmt.Fprintf(writer, "%s", err))
}

func handleAdmReq(writer http.ResponseWriter, request *http.Request) {
  var body []byte
  // input validation
  if request.Body != nil {
    if httpBody, err := ioutil.ReadAll(request.Body); err == nil {
      body = httpBody
    }
  }
  if len(body) == 0 {
    log.Warn("Recieved empty http body")
    http.Error(writer, "Empty Body", http.StatusBadRequest)
    return
  }
  contentType := request.Header.Get("Content-Type")
  if contentType != "application/json" {
    log.Warnf("Content-Type=%s but expected application/json", contentType)
    http.Error(writer, "Invalid Content-Type", http.StatusUnsupportedMediaType)
    return
  }

  admissionReviewRequest, err := httpToAdmReview(body)
  if err != nil {
    safeCrash(err, writer)
  }

  admissionReviewResponse, err := mutate(admissionReviewRequest)
  if err != nil {
    safeCrash(err, writer)
    return
  }

  responseInBytes, err := json.Marshal(admissionReviewResponse)

  if err != nil {
    safeCrash(err, writer)
    return
  }

  if _, err := writer.Write(responseInBytes); err != nil {
    safeCrash(err, writer)
  }

  log.Info("Processed admission review successfully.")
  return
}

func handleHealthcheck(writer http.ResponseWriter, request *http.Request) {
  writer.WriteHeader(http.StatusOK)
  if _, err := writer.Write([]byte("{Status: Healthy}")); err != nil {
    safeCrash(err, writer)
  }
  log.Info("Healthcheck processed")
  return
}

func main() {
  log.SetReportCaller(true)
  log.SetLevel(log.WarnLevel)
  log.SetOutput(os.Stdout)
  log.Println("Starting secret-agent server")

  tlsKeyPair := createTLSConf()

  mux := http.NewServeMux()

  mux.HandleFunc("/", handleHealthcheck)
  mux.HandleFunc("/healthcheck", handleHealthcheck)

  mux.HandleFunc("/asm-injection", handleAdmReq)

  server := &http.Server{
    Addr:   ":8443",
    Handler: mux,
    ReadTimeout:    10 * time.Second,
    WriteTimeout:   10 * time.Second,
    MaxHeaderBytes: 1 << 20, // 1048576
    TLSConfig: &tls.Config{
      Certificates: []tls.Certificate{ tlsKeyPair },
    },
  }

  log.Fatal(server.ListenAndServeTLS("", ""))
}
