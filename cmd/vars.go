package cmd

import "go.uber.org/zap"

var debug bool
var logger *zap.Logger
var openUnisonHost string
var caCertPath string
var contextName string
var forceBeta bool
