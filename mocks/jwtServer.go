// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ehsandavari/go-jwt (interfaces: IJwtServer)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	jwt "github.com/ehsandavari/go-jwt"
	gin "github.com/gin-gonic/gin"
	gomock "go.uber.org/mock/gomock"
)

// MockIJwtServer is a mock of IJwtServer interface.
type MockIJwtServer struct {
	ctrl     *gomock.Controller
	recorder *MockIJwtServerMockRecorder
}

// MockIJwtServerMockRecorder is the mock recorder for MockIJwtServer.
type MockIJwtServerMockRecorder struct {
	mock *MockIJwtServer
}

// NewMockIJwtServer creates a new mock instance.
func NewMockIJwtServer(ctrl *gomock.Controller) *MockIJwtServer {
	mock := &MockIJwtServer{ctrl: ctrl}
	mock.recorder = &MockIJwtServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIJwtServer) EXPECT() *MockIJwtServerMockRecorder {
	return m.recorder
}

// GenerateToken mocks base method.
func (m *MockIJwtServer) GenerateToken(arg0 string, arg1 ...jwt.OptionServer) (string, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GenerateToken", varargs...)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateToken indicates an expected call of GenerateToken.
func (mr *MockIJwtServerMockRecorder) GenerateToken(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateToken", reflect.TypeOf((*MockIJwtServer)(nil).GenerateToken), varargs...)
}

// GetEmail mocks base method.
func (m *MockIJwtServer) GetEmail() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEmail")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetEmail indicates an expected call of GetEmail.
func (mr *MockIJwtServerMockRecorder) GetEmail() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEmail", reflect.TypeOf((*MockIJwtServer)(nil).GetEmail))
}

// GetEmailVerified mocks base method.
func (m *MockIJwtServer) GetEmailVerified() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEmailVerified")
	ret0, _ := ret[0].(bool)
	return ret0
}

// GetEmailVerified indicates an expected call of GetEmailVerified.
func (mr *MockIJwtServerMockRecorder) GetEmailVerified() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEmailVerified", reflect.TypeOf((*MockIJwtServer)(nil).GetEmailVerified))
}

// GetId mocks base method.
func (m *MockIJwtServer) GetId() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetId")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetId indicates an expected call of GetId.
func (mr *MockIJwtServerMockRecorder) GetId() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetId", reflect.TypeOf((*MockIJwtServer)(nil).GetId))
}

// GetPhoneNumber mocks base method.
func (m *MockIJwtServer) GetPhoneNumber() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPhoneNumber")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetPhoneNumber indicates an expected call of GetPhoneNumber.
func (mr *MockIJwtServerMockRecorder) GetPhoneNumber() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPhoneNumber", reflect.TypeOf((*MockIJwtServer)(nil).GetPhoneNumber))
}

// GetPhoneNumberVerified mocks base method.
func (m *MockIJwtServer) GetPhoneNumberVerified() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPhoneNumberVerified")
	ret0, _ := ret[0].(bool)
	return ret0
}

// GetPhoneNumberVerified indicates an expected call of GetPhoneNumberVerified.
func (mr *MockIJwtServerMockRecorder) GetPhoneNumberVerified() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPhoneNumberVerified", reflect.TypeOf((*MockIJwtServer)(nil).GetPhoneNumberVerified))
}

// GetUserId mocks base method.
func (m *MockIJwtServer) GetUserId() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserId")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetUserId indicates an expected call of GetUserId.
func (mr *MockIJwtServerMockRecorder) GetUserId() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserId", reflect.TypeOf((*MockIJwtServer)(nil).GetUserId))
}

// GinMiddleware mocks base method.
func (m *MockIJwtServer) GinMiddleware() gin.HandlerFunc {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GinMiddleware")
	ret0, _ := ret[0].(gin.HandlerFunc)
	return ret0
}

// GinMiddleware indicates an expected call of GinMiddleware.
func (mr *MockIJwtServerMockRecorder) GinMiddleware() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GinMiddleware", reflect.TypeOf((*MockIJwtServer)(nil).GinMiddleware))
}

// VerifyToken mocks base method.
func (m *MockIJwtServer) VerifyToken(arg0, arg1, arg2 string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyToken", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyToken indicates an expected call of VerifyToken.
func (mr *MockIJwtServerMockRecorder) VerifyToken(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyToken", reflect.TypeOf((*MockIJwtServer)(nil).VerifyToken), arg0, arg1, arg2)
}
