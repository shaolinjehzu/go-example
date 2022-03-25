package service

import (
	"errors"
	"fmt"
	"git.itkn.ru/crypto/users/pb"
	"github.com/tarantool/go-tarantool"
	"golang.org/x/crypto/bcrypt"
	"log"
	"sync"
	"time"
)

type User struct {
	Id           uint64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	TelegramId   int64  `protobuf:"varint,2,opt,name=telegram_id,json=telegramId,proto3" json:"telegram_id,omitempty"`
	Email        string `protobuf:"bytes,3,opt,name=email,proto3" json:"email,omitempty"`
	Password     string `protobuf:"bytes,4,opt,name=password,proto3" json:"password,omitempty"`
	Nick         string `protobuf:"bytes,5,opt,name=nick,proto3" json:"nick,omitempty"`
	Avatar       string `protobuf:"bytes,6,opt,name=avatar,proto3" json:"avatar,omitempty"`
	Settings     string `protobuf:"bytes,7,opt,name=settings,proto3" json:"settings,omitempty"`
	EmailConfirm bool   `protobuf:"varint,8,opt,name=email_confirm,json=emailConfirm,proto3" json:"email_confirm,omitempty"`
	CreatedAt    uint64 `protobuf:"varint,9,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt    uint64 `protobuf:"varint,10,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
	DeletedAt    uint64 `protobuf:"varint,11,opt,name=deleted_at,json=deletedAt,proto3" json:"deleted_at,omitempty"`
}

type UsersStore interface {

	SaveReset(request *pb.ResetResponse) (*string, error)
	GetResetByToken(token string) (*pb.ResetResponse,error)

	Save(user *pb.RegisterRequest) (*uint64, error)
	Update(user *pb.User, id uint64) error
	
	FindById(id uint64) (*pb.User, error)
	
	FindAll() (
		[]*pb.User,
		error,
	)
	
	FindByEmail(email string) (
		*pb.User,
		error,
	)
	
	Delete(id string) error
	
	CreateUserSessions(session *pb.UserSession) (
		*uint64,
		error,
	)
	
	UpdateUserSessions(session *pb.UserSession) (
		*uint64,
		error,
	)
	
	GetUserSessionsIdByUserId(user_id uint64) (
		*uint64,
		error,
	)
	
	GetRoleByUser(user *pb.User) (
		*string,
		error,
	)
	
	RoleAssign(
		id uint64,
		roleId uint64,
	) error
	
	GetAllUsersWithRole() (
		[]*pb.UserWithRole,
		error,
	)

	GetAllUsersInfo() ([]*pb.UserInfo, error)
	

type TarantoolUsersStore struct {
	mutex sync.RWMutex
	db    *tarantool.Connection
}


func NewTarantoolUsersStore(
	addr string,
	user string,
	pass string,
) *TarantoolUsersStore {
	opts := tarantool.Opts{
		User: user,
		Pass: pass,
	}
	conn, err := tarantool.Connect(addr, opts)
	if err != nil {
		log.Printf("CANNOT CONNECT TARANTOOL :%v", err)
		log.Printf("HOST: %s", addr)
		log.Fatal(err)
	}
	return &TarantoolUsersStore{
		db: conn,
	}
}

func (store *TarantoolUsersStore) SaveReset(request *pb.ResetResponse) (
	*string,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*pb.User
	str := fmt.Sprintf("INSERT INTO %s (TOKEN, EMAIL, CREATED_AT) VALUES ('%s', '%s', %d)", "RESETTING_REQUESTS", request.Token, request.Email, request.CreatedAt)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	if err != nil {
		return nil, err
	}

	return &request.Token, nil

}


func (store *TarantoolUsersStore) GetResetByToken(token string) (*pb.ResetResponse,error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var response []*pb.ResetResponse
	str := fmt.Sprintf("SELECT * FROM %s WHERE TOKEN='%s'", "RESETTING_REQUESTS", token)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&response)
	if err != nil {
		return nil, err
	}

	return response[0], nil

}


func (store *TarantoolUsersStore) Save(user *pb.RegisterRequest) (
	*uint64,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*User
	fmt.Println(user)
	str := fmt.Sprintf("INSERT INTO %s (TELEGRAM_ID, EMAIL, PASSWORD, NICKNAME, AVATAR, EMAIL_CONFIRM, SETTINGS, CREATED_AT, UPDATED_AT, DELETED_AT) VALUES (0, '"+user.Email+"','"+user.Password+"', '', '', true,  '',0,0,0)", "USERS")
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	if err != nil {
		return nil, err
	}
	
	if len(users) > 0 && users[0].Id != 0 {
		return &users[0].Id, nil
	}
	
	return nil, errors.New("Cannot create user!")
	
}

func (store *TarantoolUsersStore) Update(
	user *pb.User,
	id uint64,
) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*pb.User
	str := fmt.Sprintf("UPDATE %s SET TELEGRAM_ID=%d, EMAIL='"+user.Email+"',PASSWORD='"+user.Password+"',NICKNAME='"+user.Nick+"', AVATAR='"+user.Avatar+"', EMAIL_CONFIRM=%v, SETTINGS='"+user.Settings+"', UPDATED_AT=%d WHERE ID=%d", "USERS", user.TelegramId, user.EmailConfirm, time.Now().Unix(), id)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	if err != nil {
		return err
	}
	
	return nil
}

func (store *TarantoolUsersStore) FindAll() (
	[]*pb.User,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*pb.User
	str := fmt.Sprintf("SELECT * FROM %s", "USERS")
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	if err != nil {
		return nil, err
	}
	
	if len(users) > 0 && users[0].Id != 0 {
		return users, nil
	}
	
	return nil, errors.New("Cannot delete user!")
	
}

func (store *TarantoolUsersStore) FindById(id uint64) (
	*pb.User,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*pb.User
	str := fmt.Sprintf("SELECT * FROM %s WHERE ID=%d", "USERS", id)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	if err != nil {
		return nil, err
	}
	
	return users[0], nil
}

func (store *TarantoolUsersStore) FindByEmail(email string) (
	*pb.User,
	error,
) {
	fmt.Println(email)
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*pb.User
	str := fmt.Sprintf("SELECT * FROM USERS WHERE EMAIL='"+email+"'")
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	fmt.Print("users is: ")
	fmt.Println(users[0])
	fmt.Println(err)
	if err != nil {
		return nil, err
	}

	if len(users) > 0 && users[0].Id != 0 {
		return users[0], nil
	}

	return nil, errors.New("Cannot find user by email")
}

func (store *TarantoolUsersStore) Delete(id string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*User
	str := fmt.Sprintf("DELETE FROM %s WHERE ID=%s", "USERS", id)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	if err != nil {
		return err
	}
	
	if len(users) > 0 && users[0].Id != 0 {
		return nil
	}
	
	return errors.New("Cannot delete user!")
}

func (store *TarantoolUsersStore) GetRoleByUser(user *pb.User) (
	*string,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var rbacRoleUsers []*pb.RbacRoleUser
	str := fmt.Sprintf("SELECT * FROM %s WHERE USER_ID=%d", "RBAC_ROLES_USERS", user.Id)
	log.Println(str)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&rbacRoleUsers)
	if err != nil {
		return nil, err
	}
	
	if len(rbacRoleUsers) > 0 && rbacRoleUsers[0].Id != 0 {
		log.Println(rbacRoleUsers[0].Id)
		var roles []*pb.Role
		str := fmt.Sprintf("SELECT * FROM %s WHERE ID=%d", "RBAC_ROLES", rbacRoleUsers[0].RbacRoleId)
		log.Println(str)
		err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&roles)
		if err != nil {
			return nil, err
		}
		
		if len(roles) > 0 && roles[0].Id != 0 {
			log.Println(roles[0])
			return &roles[0].Name, nil
		}
	}
	
	return nil, errors.New("Cannot find users role!")
}

func (store *TarantoolUsersStore) RoleAssign(
	id uint64,
	roleId uint64,
) error {
	log.Println(id)
	log.Println(roleId)
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var rbacRoleUsers []*pb.RbacRoleUser
	
	str := fmt.Sprintf("INSERT INTO %s VALUES (NULL, %d, %d)", "RBAC_ROLES_USERS", roleId, id)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&rbacRoleUsers)
	if err != nil {
		return err
	}
	
	if len(rbacRoleUsers) > 0 && rbacRoleUsers[0].Id != 0 {
		return nil
	}
	
	return errors.New("Cannot assign users role!")
}

func (store *TarantoolUsersStore) CreateUserSessions(session *pb.UserSession) (
	*uint64,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var sessions []*pb.UserSession
	str := fmt.Sprintf("INSERT INTO %s VALUES (NULL, %d,'%s','%s','%s',%d, %d,'%s','%s')", "USER_SESSIONS", session.UserId, session.Method, session.AccessToken, session.RefreshToken, session.CreatedAt, session.ExpiredAt, session.CreatedFromIp, session.CreatedByUserAgent)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&sessions)
	if err != nil {
		return nil, err
	}
	
	if len(sessions) > 0 && sessions[0].Id != 0 {
		return &sessions[0].Id, nil
	}
	
	return nil, errors.New("Cannot create session!")
}

func (store *TarantoolUsersStore) UpdateUserSessions(session *pb.UserSession) (
	*uint64,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var sessions []*pb.UserSession
	str := fmt.Sprintf("UPDATE %s SET METHOD_ID='%s', ACCESS_TOKEN='%s', REFRESH_TOKEN='%s',CREATED_AT=%d, EXPIRED_AT=%d,IP='%s',USER_AGENT='%s') WHERE ID=%d", "USER_SESSIONS", session.Method, session.AccessToken, session.RefreshToken, session.CreatedAt, session.ExpiredAt, session.CreatedFromIp, session.CreatedByUserAgent, session.Id)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&sessions)
	if err != nil {
		return nil, err
	}
	
	if len(sessions) > 0 && sessions[0].Id != 0 {
		return &sessions[0].Id, nil
	}
	
	return nil, errors.New("Cannot update session!")
}

func (store *TarantoolUsersStore) GetUserSessionsIdByUserId(user_id uint64) (
	*uint64,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var sessions []*pb.UserSession
	str := fmt.Sprintf("SELECT * FROM %s WHERE USER_ID=%d", "USER_SESSIONS", user_id)
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&sessions)
	if err != nil {
		return nil, err
	}
	
	if len(sessions) > 0 && sessions[0].Id != 0 {
		return &sessions[0].Id, nil
	}
	
	return nil, errors.New("Cannot get session!")
}

func (store *TarantoolUsersStore) GetAllUsersWithRole() (
	[]*pb.UserWithRole,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var users []*pb.UserWithRole
	str := fmt.Sprintf("SELECT U.ID, U.TELEGRAM_ID, U.EMAIL, U.SETTINGS, RR.ID, RR.NAME FROM USERS AS U LEFT JOIN RBAC_ROLES_USERS AS RBU ON U.ID=RBU.USER_ID LEFT JOIN RBAC_ROLES RR ON RR.ID=RBU.RBAC_ROLE_ID")
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&users)
	if err != nil {
		return nil, err
	}
	
	if len(users) > 0 && users[0].UserId != 0 {
		return users, nil
	}
	var returned []*pb.UserWithRole
	return returned, nil
}


func (store *TarantoolUsersStore) GetAllUsersInfo() (
	[]*pb.UserInfo,
	error,
) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	var usersInfo []*pb.UserInfo
	str := fmt.Sprintf("SELECT * FROM %s", "USERS_INFO")
	err := store.db.CallAsync(tarsql, []interface{}{str}).GetTyped(&usersInfo)
	if err != nil {
		return nil, err
	}

	return usersInfo, nil
}