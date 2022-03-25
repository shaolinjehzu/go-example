package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"git.itkn.ru/crypto/users/pb"
	"git.itkn.ru/crypto/users/service"
	"github.com/facebookgo/pidfile"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"time"
)

const (
	secretKey     = "ab1d90A81021bF9c6B7fD6b48314A4e7"
	tokenDuration = 1 * time.Minute

	serverCertFile   = "cert/server-cert.pem"
	serverKeyFile    = "cert/server-key.pem"
	clientCACertFile = "cert/ca-cert.pem"
)

func runGRPCServer(
	usersService pb.UsersServiceServer,
	jwtManager *service.JWTManager,
	enableTLS bool,
	listener net.Listener,
) error {
	interceptor := service.NewAuthInterceptor(jwtManager)
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(interceptor.Unary()),
		grpc.StreamInterceptor(interceptor.Stream()),
	}

	if enableTLS {
		tlsCredentials, err := loadTLSCredentials()
		if err != nil {
			return fmt.Errorf("cannot load TLS credentials: %w", err)
		}

		serverOptions = append(serverOptions, grpc.Creds(tlsCredentials))
	}

	grpcServer := grpc.NewServer(serverOptions...)

	pb.RegisterUsersServiceServer(grpcServer, usersService)

	reflection.Register(grpcServer)

	log.Printf("Start GRPC server at %s, TLS = %t", listener.Addr().String(), enableTLS)
	return grpcServer.Serve(listener)
}

func main() {

	err := godotenv.Load(".env.local")
	if err != nil {
		log.Fatal("Error loading .env.local file")
	}

	f, err := os.OpenFile(os.Getenv("LOG_PATH"), os.O_WRONLY | os.O_CREATE, 0755)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(f)

	pidfile.SetPidfilePath(os.Getenv("PID_PATH"))
	err = pidfile.Write()
	if err != nil{
		log.Panic(err)
	}
	pid, err := pidfile.Read()
	if err != nil {
		log.Panic(err)
	}

	log.Info("Start Users Service")
	runtime.GOMAXPROCS(runtime.NumCPU())

	port := flag.Int("port", 0, "the server port")
	enableTLS := flag.Bool("tls", false, "enable SSL/TLS")
	flag.Parse()

	usersStore := service.NewTarantoolUsersStore(os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASS"))

	jwtManager := service.NewJWTManager(secretKey, tokenDuration)


	billingConn, err := grpc.Dial(os.Getenv("BILLING"), grpc.WithInsecure())
	if err != nil {
		fmt.Println("cannot connect to billingService!")
	}

	defer billingConn.Close()

	billingService := pb.NewBillingServiceClient(billingConn)
	usersService := service.NewUsersService(usersStore, jwtManager, billingService)

	address := fmt.Sprintf("0.0.0.0:%d", *port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("cannot start server: ", err)
	}

	err = runGRPCServer(usersService,jwtManager, *enableTLS, listener)

	if err != nil {
		log.Fatal("cannot start server: ", err)
	}
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed client's certificate
	pemClientCA, err := ioutil.ReadFile(clientCACertFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemClientCA) {
		return nil, fmt.Errorf("failed to add client CA's certificate")
	}

	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return credentials.NewTLS(config), nil
}
