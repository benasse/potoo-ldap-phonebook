package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	_ "github.com/lib/pq"
)

var (
	ldap_user     string
	ldap_password string
)

var DB *sql.DB

func main() {

	var (
		lu string
		lp string
	)

	// parse arguments
	flag.StringVar(&lu, "lu", "", "ldap user allowed to do binding request")
	flag.StringVar(&lp, "lp", "", "ldap password allowed to do binding request")
	flag.Parse()

	ldap_user = lu
	ldap_password = lp

	// turn on debug logging
	l := hclog.New(&hclog.LoggerOptions{
		Name:  "potoo-ldap-phonebook",
		Level: hclog.Warn,
	})

	// connect to portgresql database
	connStr := "postgres://asterisk:proformatique@localhost:5432/asterisk?sslmode=disable"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}
	DB = db
	log.Println("database connected")

	// a very simple way to track authenticated connections
	authenticatedConnections := map[int]struct{}{}

	// create a new server
	s, err := gldap.NewServer(gldap.WithLogger(l), gldap.WithDisablePanicRecovery())
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}

	// create a router and add a bind handler
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create router: %s", err.Error())
	}
	r.Bind(bindHandler(authenticatedConnections))
	r.Search(searchHandler(authenticatedConnections), gldap.WithLabel("All Searches"))
	s.Router(r)
	go s.Run(":10389") // listen on port 10389

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-ctx.Done():
		log.Printf("\nstopping directory")
		s.Stop()
	}
}

func bindHandler(authenticatedConnections map[int]struct{}) func(*gldap.ResponseWriter, *gldap.Request) {
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewBindResponse(
			gldap.WithResponseCode(gldap.ResultInvalidCredentials),
		)
		defer func() {
			w.Write(resp)
		}()

		m, err := r.GetSimpleBindMessage()
		if err != nil {
			log.Printf("not a simple bind message: %s", err)
			return
		}
		if m.UserName == ldap_user && string(m.Password) == ldap_password {
			authenticatedConnections[r.ConnectionID()] = struct{}{} // mark connection as authenticated
			resp.SetResultCode(gldap.ResultSuccess)
			log.Println("bind success")
			return
		}
	}
}

func searchHandler(authenticatedConnections map[int]struct{}) func(w *gldap.ResponseWriter, r *gldap.Request) {
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
		defer func() {
			w.Write(resp)
		}()
		// check if connection is authenticated
		if _, ok := authenticatedConnections[r.ConnectionID()]; !ok {
			log.Printf("connection %d is not authorized", r.ConnectionID())
			resp.SetResultCode(gldap.ResultAuthorizationDenied)
			return
		}
		m, err := r.GetSearchMessage()
		if err != nil {
			log.Printf("not a search message: %s", err)
			return
		}
		log.Printf("search base dn: %s", m.BaseDN)
		log.Printf("search scope: %d", m.Scope)
		log.Printf("search filter: %s", m.Filter)

		if m.BaseDN == "ou=phonebook,cn=potoo,dc=pm" {

			// TODO: make something better to parse filter may be with https://github.com/janstuemmel/go-ldap-filter
			// or https://github.com/alecthomas/participle
			rePhone := regexp.MustCompile(`telephoneNumber=(\*\d*\*|\d*[*]{1}|\d*)`)
			reCn := regexp.MustCompile(`cn=(\*[a-zA-Z0-9_-]*\*|[a-zA-Z0-9_-]*\*|[a-zA-Z0-9_-]*)`)

			query := `
                        SELECT DISTINCT
                        CONCAT('user-', userfeatures.uuid, '-', linefeatures.number) AS uid,
                        CONCAT(userfeatures.firstname, ' ',userfeatures.lastname) AS cn,
                        COALESCE(linefeatures.number, '') AS telephoneNumber
                        FROM
                        public.userfeatures
                        LEFT JOIN user_line ON (user_line.user_id = userfeatures.id)
                        LEFT JOIN linefeatures ON (user_line.line_id = linefeatures.id)
                        `

			phonePatern := rePhone.FindSubmatch([]byte(m.Filter))
			cnPatern := reCn.FindSubmatch([]byte(m.Filter))

			if phonePatern != nil && cnPatern != nil {
				query += "WHERE linefeatures.number LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' OR userfeatures.firstname LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' OR userfeatures.lastname LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' "
			} else if phonePatern != nil {
				query += "WHERE linefeatures.number LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' "
			} else if cnPatern != nil {
				query += "WHERE LOWER(userfeatures.firstname) LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' OR LOWER(userfeatures.lastname) LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' "
			}

			query += `UNION ALL
                        SELECT
                        CONCAT('usermobile-', userfeatures.uuid,'-', userfeatures.mobilephonenumber) AS uid,
                        CONCAT(userfeatures.firstname, ' ',userfeatures.lastname,' (Mobile)') AS cn,
                        COALESCE(userfeatures.mobilephonenumber, '') AS telephoneNumber
                        FROM
                        public.userfeatures
                        `

			if phonePatern != nil && cnPatern != nil {
				query += "WHERE userfeatures.mobilephonenumber LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' OR userfeatures.firstname LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' OR userfeatures.lastname LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' "
			} else if phonePatern != nil {
				query += "WHERE userfeatures.mobilephonenumber LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' "
			} else if cnPatern != nil {
				query += "WHERE LOWER(userfeatures.firstname) LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' OR LOWER(userfeatures.lastname) LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' "
			}
			query += ""
			query += `UNION ALL
                        SELECT
                        CONCAT('group-', groupfeatures.uuid,'-', extensions.exten) AS uid,
                        groupfeatures.label AS cn,
                        extensions.exten AS telephoneNumber
                        FROM public.groupfeatures
                        LEFT JOIN extensions ON (extensions.typeval = groupfeatures.id::varchar) WHERE extensions.type = 'group'
                        `

			if phonePatern != nil && cnPatern != nil {
				query += "AND extensions.exten LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' OR groupefeatures.label LIKE '"
				query += strings.ReplaceAll(string(cnPatern[1]), "*", "%")
				query += "' "
			} else if phonePatern != nil {
				query += "AND extensions.exten LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' "
			} else if cnPatern != nil {
				query += "AND groupfeatures.label LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' "
			}

			query += ""
			query += `UNION ALL
                        SELECT
                        CONCAT('queue-', queuefeatures.id,'-', extensions.exten) AS uid,
                        queuefeatures.displayname AS cn,
                        extensions.exten AS telephoneNumber
                        FROM public.queuefeatures
                        LEFT JOIN extensions ON (extensions.typeval = queuefeatures.id::varchar) WHERE extensions.type = 'queue'
                        `

			if phonePatern != nil && cnPatern != nil {
				query += "AND extensions.exten LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' OR queuefeatures.displayname LIKE '"
				query += strings.ReplaceAll(string(cnPatern[1]), "*", "%")
				query += "' "
			} else if phonePatern != nil {
				query += "AND extensions.exten LIKE '"
				query += strings.ReplaceAll(string(phonePatern[1]), "*", "%")
				query += "' "
			} else if cnPatern != nil {
				query += "AND queuefeatures.displayname LIKE '"
				query += strings.ReplaceAll(strings.ToLower(string(cnPatern[1])), "*", "%")
				query += "' "
			}

			query += "ORDER BY cn LIMIT 20;"

			//log.Println(query)

			var (
				uid             string
				cn              string
				telephoneNumber string
			)

			rows, err := DB.Query(query)
			if err != nil {
				panic(err)
			}
			defer rows.Close()
			for rows.Next() {
				err := rows.Scan(&uid, &cn, &telephoneNumber)
				if err != nil {
					log.Fatal(err)
				}
				//log.Println(uid, cn, telephoneNumber)
				entry := r.NewSearchResponseEntry(
					"uid="+uid+",ou=phonebook,cn=potoo,dc=pm",
					gldap.WithAttributes(map[string][]string{
						"objectclass":     {"top", "person"},
						"uid":             {uid},
						"cn":              {cn},
						"telephoneNumber": {telephoneNumber},
					}),
				)
				w.Write(entry)
				resp.SetResultCode(gldap.ResultSuccess)
			}
		}
	}
}
