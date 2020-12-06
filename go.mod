module git.narnian.us/lordwelch/sshrimp

go 1.13

replace github.com/b-b3rn4rd/gocfn => github.com/stoggi/gocfn v0.0.0-20200214083946-6202cea979b9

require (
	cloud.google.com/go v0.63.0
	git.narnian.us/lordwelch/aws-oidc v0.0.2
	github.com/AlecAivazis/survey/v2 v2.1.0
	github.com/BurntSushi/toml v0.3.1
	github.com/aws/aws-lambda-go v1.19.0
	github.com/aws/aws-sdk-go v1.33.21
	github.com/awslabs/goformation/v4 v4.14.0
	github.com/coreos/go-oidc v2.0.0+incompatible
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/magefile/mage v1.10.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98
)
