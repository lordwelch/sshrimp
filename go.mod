module github.com/stoggi/sshrimp

go 1.14

replace github.com/b-b3rn4rd/gocfn => github.com/stoggi/gocfn v0.0.0-20200214083946-6202cea979b9

replace github.com/stoggi/aws-oidc => ./internal/aws-oidc

require (
	cloud.google.com/go v0.38.0
	github.com/AlecAivazis/survey/v2 v2.0.5
	github.com/BurntSushi/toml v0.3.1
	github.com/aws/aws-lambda-go v1.13.3
	github.com/aws/aws-sdk-go v1.25.43
	github.com/awslabs/goformation/v4 v4.4.0
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/magefile/mage v1.9.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stoggi/aws-oidc v0.0.0-20190621033350-d7c8067c7515
	golang.org/x/crypto v0.0.0-20191128160524-b544559bb6d1
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	golang.org/x/sys v0.0.0-20190813064441-fde4db37ae7a // indirect
	google.golang.org/api v0.21.0 // indirect
	google.golang.org/genproto v0.0.0-20200413115906-b5235f65be36
	google.golang.org/grpc v1.28.1 // indirect
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
)
