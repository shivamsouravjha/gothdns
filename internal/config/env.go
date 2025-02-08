package config

type Environment struct {
	Addr string `env:"ADDR,default=0.0.0.0,required=true"`
	Port int    `env:"PORT,default=53,required=true"`
}
