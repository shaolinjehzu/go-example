package service

import (
	"context"
	"fmt"
	"git.itkn.ru/crypto/users/pb"
	"github.com/pkg/errors"
	"github.com/rivo/sessions"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"net/smtp"
	"strconv"
	"time"
)

type UsersService struct{
	usersStore UsersStore
	jwtManager *JWTManager
	billingService pb.BillingServiceClient
}

func NewUsersService(usersStore UsersStore, jwtManager *JWTManager, billingService pb.BillingServiceClient) *UsersService {
	return &UsersService{usersStore, jwtManager, billingService}
}

func (service *UsersService) ResetPass(ctx context.Context, request *pb.LoginRequest) (*pb.ResetResponse, error) {
	fmt.Println(request)
	user, err := service.usersStore.FindByEmail(request.Email)
	if err != nil {
		return nil, err
	}
	token, err := sessions.RandomID(22)
	if err != nil {
		return nil, err
	}

	tokenCreated := uint64(time.Now().Unix())

	_, err = service.usersStore.SaveReset(&pb.ResetResponse{
		Token:     token,
		Email:     user.Email,
		CreatedAt: tokenCreated,
	})
	if err != nil {
		return nil, err
	}

	to := []string{
		request.Email,
	}

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	msg := []byte("To: "+request.Email+"\r\n" +     "Subject: Alicanto password reset!\r\n" +     "\r\n" +     "Your code is: "+token +".\r\n")
	auth := smtp.PlainAuth("", from, password, smtpHost)

	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, msg)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	fmt.Println("Email Sent Successfully!")

	return &pb.ResetResponse{
		Token: token,
		Email: user.Email,
		CreatedAt: tokenCreated,
	}, nil
}

func (service *UsersService) ResetPassConfirm(ctx context.Context, request *pb.ResetConfirmRequest) (*pb.Request, error) {
	fmt.Println(request)
	if request.Password != request.ConfirmPassword {
		return nil, errors.New("Password does not match")
	}
	req, err := service.usersStore.GetResetByToken(request.Token)
	if err != nil {
		return nil, err
	}

	user, err := service.usersStore.FindByEmail(req.Email)
	if err != nil {
		return nil, err
	}

	user.Password, err = HashPass(request.Password)
	if err != nil {
		return nil, err
	}

	err = service.usersStore.Update(user, user.Id)
	if err != nil {
		return nil, err
	}

	return &pb.Request{}, nil
}

func (service *UsersService) Login(ctx context.Context, request *pb.LoginRequest) (*pb.LoginResponse, error) {
	fmt.Println(request)
	md, _ := metadata.FromIncomingContext(ctx)

	user, err := service.usersStore.FindByEmail(request.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot find user")
	}

	if !IsCorrectPassword(user.Password, request.Password) {
		return nil, status.Errorf(codes.NotFound, "incorrect username/password")
	}

	role, err := service.usersStore.GetRoleByUser(user)
	if err != nil{
		return nil, status.Errorf(codes.NotFound, "cannot find users role: %v", err)
	}
	AccessToken, err := service.jwtManager.GenerateAccess(user, role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate access token %v", err)
	}

	RefreshToken, err := service.jwtManager.GenerateRefresh(user, role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate access token %v", err)
	}

	claims, err := service.jwtManager.Verify(AccessToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot get users claims %v", err)
	}

	id, err := service.usersStore.CreateUserSessions(&pb.UserSession{
		Id:                 0,
		UserId:             user.Id,
		Method:             1,
		AccessToken:        AccessToken,
		RefreshToken:       RefreshToken,
		CreatedAt:          uint64(time.Now().Unix()),
		ExpiredAt:          uint64(claims.ExpiresAt),
		CreatedFromIp:      "",
		CreatedByUserAgent: md["grpcgateway-user-agent"][0],
	})
	if err != nil{
		return nil, status.Errorf(codes.Internal, "cannot create users session: %v", err)
	}
	if id != nil{
		res := &pb.LoginResponse{
			Tokens: &pb.Tokens{AccessToken: AccessToken, RefreshToken: RefreshToken},
			User: user,
			Role: *role,
		}
		return res, nil
	}
	return nil, status.Errorf(codes.Internal, "cannot authorize user")
}

func (service *UsersService) Refresh(ctx context.Context, request *pb.RefreshRequest) (*pb.LoginResponse, error) {

	md, _ := metadata.FromIncomingContext(ctx)

	claims, err := service.jwtManager.Verify(request.RefreshToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot parse token: %v", err)
	}
	user, err := service.usersStore.FindByEmail(claims.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot find user: %v", err)
	}

	role, err := service.usersStore.GetRoleByUser(user)
	if err != nil{
		return nil, status.Errorf(codes.NotFound, "cannot find users role: %v", err)
	}
	AccessToken, err := service.jwtManager.GenerateAccess(user, &claims.Role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate access token %v", err)
	}

	RefreshToken, err := service.jwtManager.GenerateRefresh(user, &claims.Role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate access token %v", err)
	}

	claims, err = service.jwtManager.Verify(AccessToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot get users claims %v", err)
	}

	sessionId, err := service.usersStore.GetUserSessionsIdByUserId(user.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot get users session %v", err)
	}


	id, err := service.usersStore.UpdateUserSessions(&pb.UserSession{
		Id:                 *sessionId,
		UserId:             user.Id,
		Method:             1,
		AccessToken:        AccessToken,
		RefreshToken:       RefreshToken,
		CreatedAt:          uint64(time.Now().Unix()),
		ExpiredAt:          uint64(claims.ExpiresAt),
		CreatedFromIp:      "",
		CreatedByUserAgent: md["grpcgateway-user-agent"][0],
	})
	if err != nil{
		return nil, status.Errorf(codes.Internal, "cannot update users session: %v", err)
	}
	if id != nil{
		res := &pb.LoginResponse{
			Tokens: &pb.Tokens{AccessToken: AccessToken, RefreshToken: RefreshToken},
			User: user,
			Role: *role,
		}
		return res, nil
	}
	return nil, status.Errorf(codes.Internal, "cannot authorize user")
}

func (service *UsersService) Registration(ctx context.Context, request *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if request.GetPassword() == request.GetConfirmPassword() {
		
		var err error

		request.Password, err = HashPass(request.Password)
		if err != nil {
			return nil, err
		}
		id, err := service.usersStore.Save(request)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "cannot save user: %v", err)
		}

		_, err = service.billingService.CreateReferralUserAccount(ctx, &pb.ReferralUserAccount{UserId: *id})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "cannot create referral users account")
		}

		_, err = service.billingService.CreateLostProfitUserAccount(ctx, &pb.LostProfitUserAccount{UserId: *id})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "cannot create lost profit users account")
		}

		_, err = service.billingService.CreateCryptoUserAccount(ctx, &pb.CryptoUserAccount{UserId: *id})
		if err != nil {
		   log.Info(err)
			return nil, status.Errorf(codes.Internal, "cannot create crypto users account")
		}

		err = service.usersStore.RoleAssign(*id, 5)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "cannot assign role to user: %v", err)
		}
		return &pb.RegisterResponse{
			Email: request.Email,
		}, nil
	}
	return nil, status.Errorf(codes.Internal, "cannot register user: %v", "passwords do not match")
}

func (service *UsersService) GetAllUserInfos(ctx context.Context, request *pb.Request) (*pb.UserInfoResponse, error) {

	usersInfo, err :=  service.usersStore.GetAllUsersInfo()
	if err != nil {
		return nil, err
	}
	return &pb.UserInfoResponse{UsersInfo: usersInfo}, nil
}

func (service *UsersService) GetAllUsersWithRole(ctx context.Context, req *pb.Request) (*pb.UserWithRoleResponse, error) {
	users, err := service.usersStore.GetAllUsersWithRole()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot get users: %v", err)
	}
	return &pb.UserWithRoleResponse{Users: users}, nil

}


func(service *UsersService) GetUser(ctx context.Context, req *pb.User) (*pb.UserResponse, error) {

	user, err := service.usersStore.FindById(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot get user: %v", err)
	}
	return &pb.UserResponse{
		User: user,
	}, nil
}

func(service *UsersService) GetAllUsers(ctx context.Context, req *pb.Request) (*pb.UserResponse, error) {

	users, err := service.usersStore.FindAll()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot get users: %v", err)
	}
	return &pb.UserResponse{
		Users: users,
	}, nil
}

func(service *UsersService) UpdateUser(ctx context.Context, req *pb.User) (*pb.UserResponse, error) {
	if req.Password != "" {
		var err error
		req.Password, err = HashPass(req.Password)
		if err != nil {
			return nil, err
		}
	}
		err := service.usersStore.Update(req, req.Id)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "cannot update user: %v", err)
		}
		req.Password = ""
		return &pb.UserResponse{
			User: req,
		}, nil

	}

func(service *UsersService) DeleteUser(ctx context.Context, req *pb.User) (*pb.UserResponse, error) {

	err := service.usersStore.Delete(strconv.FormatUint(req.GetId(), 64))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot get user: %v", err)
	}
	return &pb.UserResponse{
		User: nil,
	}, nil
}



func HashPass(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("cannot hash password: %w", err)
	}
	return string(hashedPassword), nil
}

func IsCorrectPassword(password string, enteredPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(enteredPassword))
	return err == nil
}