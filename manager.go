package gominisession

import (
	"time"

	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"

	"github.com/mssola/user_agent"
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
)

type SessionManagerConfig struct {
	ProjectId string
	Kind      string
}

func NewSessionManager(config SessionManagerConfig) *SessionManager {
	ret := new(SessionManager)
	if config.ProjectId == "" {
		ret.projectId = ""
	} else {
		ret.projectId = config.ProjectId
	}
	if config.Kind == "" {
		ret.loginIdKind = "LoginId"
	} else {
		ret.loginIdKind = config.Kind
	}
	return ret
}

type AccessTokenConfig struct {
	IP        string
	UserAgent string
	LoginType string
}

func (obj *SessionManager) NewAccessToken(ctx context.Context, userName string, config AccessTokenConfig) (*AccessToken, error) {
	//
	ret := new(AccessToken)
	ret.gaeObject = new(GaeAccessTokenItem)
	deviceId, loginId, loginTime := obj.MakeLoginId(userName, config.IP, config.UserAgent)
	ret.gaeObject.ProjectId = obj.projectId

	ret.gaeObject.LoginId = loginId
	ret.gaeObject.IP = config.IP
	ret.gaeObject.Type = config.LoginType
	ret.gaeObject.LoginTime = loginTime
	ret.gaeObject.DeviceID = deviceId
	ret.gaeObject.UserName = userName
	ret.gaeObject.UserAgent = config.UserAgent

	ret.ItemKind = obj.loginIdKind
	ret.gaeObjectKey = obj.NewAccessTokenGaeObjectKey(ctx, userName, deviceId, nil)

	_, e := datastore.Put(ctx, ret.gaeObjectKey, ret.gaeObject)
	return ret, e
}

func (obj *SessionManager) NewAccessTokenFromLoginId(ctx context.Context, loginId string) (*AccessToken, error) {
	idInfo, err := obj.ExtractUserFromLoginId(loginId)
	if err != nil {
		return nil, err
	}
	ret := new(AccessToken)
	ret.ItemKind = obj.loginIdKind
	ret.gaeObject = new(GaeAccessTokenItem)
	ret.gaeObject.ProjectId = obj.projectId
	ret.gaeObjectKey = obj.NewAccessTokenGaeObjectKey(ctx, idInfo.UserName, idInfo.DeviceId, nil)
	ret.gaeObject.LoginId = loginId

	err = ret.LoadFromDB(ctx)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (obj *SessionManager) NewAccessTokenGaeObjectKey(ctx context.Context, userName string, deviceId string, parentKey *datastore.Key) *datastore.Key {
	return datastore.NewKey(ctx, obj.loginIdKind, obj.MakeGaeObjectKeyStringId(userName, deviceId), 0, parentKey)
}

func (obj *SessionManager) MakeGaeObjectKeyStringId(userName string, deviceId string) string {
	return obj.loginIdKind + ":" + obj.projectId + ":" + userName + ":" + deviceId
}

//
//
//
type LoginIdInfo struct {
	DeviceId string
	UserName string
}

func (obj *SessionManager) ExtractUserFromLoginId(loginId string) (*LoginIdInfo, error) {
	binary := []byte(loginId)
	if len(binary) <= 28+28+1 {
		return nil, ErrorExtract
	}
	//
	binaryUser, err := base64.StdEncoding.DecodeString(string(binary[28*2:]))
	if err != nil {
		return nil, ErrorExtract
	}
	//
	ret := new(LoginIdInfo)
	ret.DeviceId = string(binary[28 : 28*2])
	ret.UserName = string(binaryUser)
	return ret, nil
}

func (obj *SessionManager) MakeDeviceId(userName string, ip string, userAgent string) string {
	uaObj := user_agent.New(userAgent)
	sha1Hash := sha1.New()
	b, _ := uaObj.Browser()
	io.WriteString(sha1Hash, b)
	io.WriteString(sha1Hash, uaObj.OS())
	io.WriteString(sha1Hash, uaObj.Platform())
	return base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))
}

func (obj *SessionManager) MakeLoginId(userName string, ip string, userAgent string) (string, string, time.Time) {
	t := time.Now()
	DeviceID := obj.MakeDeviceId(userName, ip, userAgent)
	loginId := ""
	sha1Hash := sha1.New()
	io.WriteString(sha1Hash, DeviceID)
	io.WriteString(sha1Hash, userName)
	io.WriteString(sha1Hash, fmt.Sprintf("%X%X", t.UnixNano(), rand.Int63()))
	loginId = base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))
	loginId += DeviceID
	loginId += base64.StdEncoding.EncodeToString([]byte(userName))
	return DeviceID, loginId, t
}

func (obj *SessionManager) CheckLoginId(ctx context.Context, loginId string, remoteAddr string, userAgent string) (bool, *AccessToken, error) {
	//
	var loginIdObj *AccessToken
	var err error

	loginIdObj, err = obj.NewAccessTokenFromLoginId(ctx, loginId)
	if err != nil {
		return false, nil, err
	}
	reqDeviceId, _, _ := obj.MakeLoginId(loginIdObj.GetUserName(), remoteAddr, userAgent)
	if loginIdObj.GetDeviceId() != reqDeviceId || loginIdObj.GetLoginId() != loginId {
		return false, loginIdObj, nil
	}
	loginIdObj.UpdateMemcache(ctx)

	return true, loginIdObj, nil
}

func (obj *SessionManager) Login(ctx context.Context, userName string, remoteAddr string, userAgent string, loginType string) (*AccessToken, error) {
	loginIdObj, err1 := obj.NewAccessToken(ctx, userName, AccessTokenConfig{
		IP:        remoteAddr,
		UserAgent: userAgent,
		LoginType: loginType,
	})
	if err1 == nil {
		loginIdObj.UpdateMemcache(ctx)
	}
	return loginIdObj, err1
}

func (obj *SessionManager) Logout(ctx context.Context, loginId string, remoteAddr string, userAgent string) error {
	isLogin, loginIdObj, err := obj.CheckLoginId(ctx, loginId, remoteAddr, userAgent)
	if err != nil {
		return err
	}
	if isLogin == false {
		return nil
	}
	return loginIdObj.Logout(ctx)
}
