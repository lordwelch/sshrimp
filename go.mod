module github.com/stoggi/sshrimp

go 1.14

replace github.com/b-b3rn4rd/gocfn => github.com/stoggi/gocfn v0.0.0-20200214083946-6202cea979b9

replace github.com/stoggi/aws-oidc => ./internal/aws-oidc

require (
	cloud.google.com/go v0.63.0
	github.com/AlecAivazis/survey/v2 v2.1.0
	github.com/BurntSushi/toml v0.3.1
	github.com/aws/aws-lambda-go v1.19.0
	github.com/aws/aws-sdk-go v1.33.21
	github.com/awslabs/goformation/v4 v4.14.0
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/imdario/mergo v0.3.10 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/magefile/mage v1.10.0
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.6.0
	github.com/stoggi/aws-oidc v0.0.0-20190621033350-d7c8067c7515
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	golang.org/x/sys v0.0.0-20200806125547-5acd03effb82 // indirect
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
)
