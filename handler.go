package accesslogger

import (
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/najeira/ltsv"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/peer"
)

var _ grpc.UnaryServerInterceptor = UnaryAccessLogHandler

type loggerKey struct{}
type loggerNote struct {
	Note map[string]string
}

type Request struct {
	time     time.Time
	service  string
	method   string
	status   string
	code     codes.Code
	desc     string
	duration time.Duration
	level    string
	remote   string
	tls      string
	cipher   string
}

var logger io.Writer = os.Stdout

func SetLogger(w io.Writer) {
	logger = w
}

func UnaryAccessLogHandler(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	ctx = context.WithValue(ctx, loggerKey{}, &loggerNote{})
	defer log(ctx, info, time.Now().UTC(), err)
	return handler(ctx, req)
}

func Note(ctx context.Context, key, value string) {
	note, ok := ctx.Value(loggerKey{}).(*loggerNote)
	if !ok {
		return
	}
	note.Note[key] = value
}

func log(ctx context.Context, info *grpc.UnaryServerInfo, start time.Time, grpcErr error) {
	code := grpc.Code(grpcErr)
	desc := grpc.ErrorDesc(grpcErr)
	service := ""
	method := ""
	fullMethod := info.FullMethod
	fullMethodSlice := strings.Split(fullMethod, "/")
	if len(fullMethodSlice) == 3 {
		service = fullMethodSlice[1]
		method = fullMethodSlice[2]
	}
	duration := time.Since(start)

	var addr string
	var tls string
	var cipher string
	var network string
	if pr, ok := peer.FromContext(ctx); ok {
		if pr.AuthInfo != nil {
			if info, ok := pr.AuthInfo.(credentials.TLSInfo); ok {
				tls = tlsString(info.State.Version)
				cipher = cipherSuiteString(info.State.CipherSuite)
			}
		}
		network = pr.Addr.Network()
		if tcpAddr, ok := pr.Addr.(*net.TCPAddr); ok {
			addr = tcpAddr.IP.String()
		} else {
			addr = pr.Addr.String()
		}
	}

	var level string
	switch code {
	case codes.OK:
		level = "info"
	case codes.Unknown, codes.Internal:
		level = "error"
	default:
		level = "warn"
	}

	w := ltsv.NewWriter(logger)
	err := w.Write(map[string]interface{}{
		"time":     time.Now().Format(time.RFC3339),
		"service":  service,
		"method":   method,
		"status":   code.String(),
		"code":     uint32(code),
		"duration": duration.Nanoseconds() / int64(time.Millisecond),
		"error":    desc,
		"level":    level,
		"remote":   addr,
		"tls":      tls,
		"cipher":   cipher,
	})
	if err != nil {
		// fallback
		grpclog.Printf("ltsv encode error: %v", err)
		return
	}
	w.Flush()
}
