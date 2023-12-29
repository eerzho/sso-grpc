package grpcapp

import (
	"fmt"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"net"
	authgrpc "sso/internal/grpc/auth"
)

type App struct {
	log        *slog.Logger
	grpcServer *grpc.Server
	port       int
}

func New(log *slog.Logger, authService authgrpc.Auth, port int) *App {
	grpcServer := grpc.NewServer()

	authgrpc.Register(grpcServer, authService)

	return &App{
		log:        log,
		grpcServer: grpcServer,
		port:       port,
	}
}

func (this *App) MustRun() {
	if err := this.Run(); err != nil {
		panic(err)
	}
}

func (this *App) Run() error {
	const op = "grpcapp.Run"

	log := this.log.With(
		slog.String("op", op),
		slog.Int("port", this.port),
	)

	log.Info("starting gRPC server")

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", this.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("gRPC server is running", slog.String("addr", l.Addr().String()))

	if err := this.grpcServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (this *App) Stop() {
	const op = "grpcapp.Stop"

	this.log.With(slog.String("op", op)).Info("stopping gRPC server", slog.Int("port", this.port))

	this.grpcServer.GracefulStop()
}
