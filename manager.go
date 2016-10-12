package gominisession

import (
	"time"

	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"

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

func MakeAccessTokenConfigFromRequest(r http.Request) AccessTokenConfig {
	return AccessTokenConfig{IP: r.RemoteAddr, UserAgent: r.UserAgent()}
}

func (obj *SessionManager) NewAccessToken(ctx context.Context, userName string, config AccessTokenConfig) (*AccessToken, error) {
	ret := new(AccessToken)
	ret.gaeObject = new(GaeAccessTokenItem)
	loginTime := time.Now()
	idInfoObj := obj.NewLoginIdInfo(userName, config)
	ret.gaeObject.ProjectId = obj.projectId

	ret.gaeObject.LoginId = idInfoObj.LoginId
	ret.gaeObject.IP = config.IP
	ret.gaeObject.Type = config.LoginType
	ret.gaeObject.LoginTime = loginTime
	ret.gaeObject.DeviceID = idInfoObj.DeviceId
	ret.gaeObject.UserName = userName
	ret.gaeObject.UserAgent = config.UserAgent

	ret.ItemKind = obj.loginIdKind
	ret.gaeObjectKey = obj.NewAccessTokenGaeObjectKey(ctx, idInfoObj)

	_, e := datastore.Put(ctx, ret.gaeObjectKey, ret.gaeObject)
	return ret, e
}

func (obj *SessionManager) NewAccessTokenFromLoginId(ctx context.Context, loginId string) (*AccessToken, error) {
	idInfo, err := obj.NewLoginIdInfoFromLoginId(loginId)
	if err != nil {
		return nil, err
	}
	ret := new(AccessToken)
	ret.ItemKind = obj.loginIdKind
	ret.gaeObject = new(GaeAccessTokenItem)
	ret.gaeObject.ProjectId = obj.projectId
	ret.gaeObjectKey = obj.NewAccessTokenGaeObjectKey(ctx, idInfo)
	ret.gaeObject.LoginId = loginId

	err = ret.LoadFromDB(ctx)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (obj *SessionManager) NewAccessTokenGaeObjectKey(ctx context.Context, idInfoObj *LoginIdInfo) *datastore.Key {
	return datastore.NewKey(ctx, obj.loginIdKind, obj.MakeGaeObjectKeyStringId(idInfoObj.UserName, idInfoObj.DeviceId), 0, nil)
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
	LoginId  string
}

func (obj *SessionManager) NewLoginIdInfoFromLoginId(loginId string) (*LoginIdInfo, error) {
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

func (obj *SessionManager) MakeDeviceId(userName string, info AccessTokenConfig) string {
	uaObj := user_agent.New(info.UserAgent)
	sha1Hash := sha1.New()
	b, _ := uaObj.Browser()
	io.WriteString(sha1Hash, b)
	io.WriteString(sha1Hash, uaObj.OS())
	io.WriteString(sha1Hash, uaObj.Platform())
	return base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))
}

func (obj *SessionManager) NewLoginIdInfo(userName string, config AccessTokenConfig) *LoginIdInfo {
	DeviceID := obj.MakeDeviceId(userName, config)
	loginId := ""
	sha1Hash := sha1.New()
	io.WriteString(sha1Hash, DeviceID)
	io.WriteString(sha1Hash, userName)
	io.WriteString(sha1Hash, fmt.Sprintf("%X", rand.Int63()))
	loginId = base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))
	loginId += DeviceID
	loginId += base64.StdEncoding.EncodeToString([]byte(userName))
	ret := new(LoginIdInfo)
	ret.DeviceId = DeviceID
	ret.UserName = userName
	ret.LoginId = loginId
	return ret
}

type CheckLoginIdInfo struct {
	IsLogin        bool
	AccessTokenObj *AccessToken
	LoginIdInfoObj *LoginIdInfo
}

func (obj *SessionManager) CheckLoginId(ctx context.Context, loginId string, config AccessTokenConfig) (*CheckLoginIdInfo, error) {
	ret := new(CheckLoginIdInfo)
	accessTokenObj, err := obj.NewAccessTokenFromLoginId(ctx, loginId)
	if err != nil {
		ret.IsLogin = false
		return ret, err
	}

	// todo
	loginIdInfoObj := obj.NewLoginIdInfo(accessTokenObj.GetUserName(), config)
	ret.AccessTokenObj = accessTokenObj
	ret.LoginIdInfoObj = loginIdInfoObj
	if accessTokenObj.GetDeviceId() != loginIdInfoObj.DeviceId || accessTokenObj.GetLoginId() != loginId {
		ret.IsLogin = false
		return ret, nil
	}
	accessTokenObj.UpdateMemcache(ctx)
	//

	ret.IsLogin = true
	ret.AccessTokenObj = accessTokenObj
	ret.LoginIdInfoObj = loginIdInfoObj
	return ret, nil
}

func (obj *SessionManager) Login(ctx context.Context, userName string, config AccessTokenConfig) (*AccessToken, error) {
	loginIdObj, err1 := obj.NewAccessToken(ctx, userName, config)
	if err1 == nil {
		loginIdObj.UpdateMemcache(ctx)
	}
	return loginIdObj, err1
}

func (obj *SessionManager) Logout(ctx context.Context, loginId string, config AccessTokenConfig) error {
	checkLoginIdInfoObj, err := obj.CheckLoginId(ctx, loginId, config)
	if err != nil {
		return err
	}
	if checkLoginIdInfoObj.IsLogin == false {
		return nil
	}
	return checkLoginIdInfoObj.AccessTokenObj.Logout(ctx)
}
