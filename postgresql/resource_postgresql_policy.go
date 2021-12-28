package postgresql

import (
	"bytes"
	"database/sql"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lib/pq"
	"log"
	"strings"
)

const (
	policyNameAttr   = "name"
	policySchemaAttr = "schema"
	policyTableAttr  = "table"
	policyToAttr     = "to"
	policyUsingAttr  = "using"
)

func resourcePostgreSQLPolicy() *schema.Resource {
	return &schema.Resource{
		Create: PGResourceFunc(resourcePostgreSQLPolicyCreate),
		Read:   PGResourceFunc(resourcePostgreSQLPolicyRead),
		Update: PGResourceFunc(resourcePostgreSQLPolicyUpdate),
		Delete: PGResourceFunc(resourcePostgreSQLPolicyDelete),
		Exists: PGResourceExistsFunc(resourcePostgreSQLPolicyExists),

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			policyNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Sets policy name",
			},
			policySchemaAttr: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Sets the target schema for policy",
			},
			policyTableAttr: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Sets the target table for policy",
			},
			policyToAttr: {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Sets the role for policy to be used by",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			policyUsingAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Sets the RLS filter",
			},
		},
	}
}

func resourcePostgreSQLPolicyCreate(db *DBConnection, d *schema.ResourceData) error {
	policySchema := d.Get(policySchemaAttr).(string)
	policyTable := d.Get(policyTableAttr).(string)
	policyName := d.Get(policyNameAttr).(string)
	policyToRaw := d.Get(policyToAttr).([]interface{})
	policyUsing := d.Get(policyUsingAttr).(string)

	policyTo := make([]string, len(policyToRaw))
	for i := range policyToRaw {
		policyTo[i] = policyToRaw[i].(string)
	}

	txn, err := startTransaction(db.client, db.client.databaseName)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	b1 := bytes.NewBufferString("ALTER TABLE ")
	fmt.Fprint(b1,
		pq.QuoteIdentifier(policySchema), ".", pq.QuoteIdentifier(policyTable),
		" ENABLE ROW LEVEL SECURITY",
	)
	if _, err := txn.Exec(b1.String()); err != nil {
		return err
	}

	b2 := bytes.NewBufferString("CREATE POLICY ")
	fmt.Fprint(b2,
		pq.QuoteIdentifier(policyName),
		" ON ",
		pq.QuoteIdentifier(policySchema), ".", pq.QuoteIdentifier(policyTable),
		" TO ",
		strings.Join(policyTo, ", "), // TODO: quote policyTo
		" USING (",
		policyUsing,
		")",
	)
	if _, err := txn.Exec(b2.String()); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error creating Policy: %w", err)
	}

	d.SetId(generatePolicyID(d))

	return resourcePostgreSQLPolicyRead(db, d)
}

func resourcePostgreSQLPolicyRead(db *DBConnection, d *schema.ResourceData) error {
	var policySchema string
	var policyTable string
	var policyName string
	var policyTo []string
	var policyUsing string

	policySchema, policyTable, policyName = getInfoFromID(d.Id())

	err := db.QueryRow(
		"SELECT roles :: varchar[], qual FROM pg_policies WHERE schemaname = $1 AND tablename = $2 AND policyname = $3",
		policySchema, policyTable, policyName,
	).Scan(pq.Array(&policyTo), &policyUsing)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL policy (%q ON (%q.%q) not found", policyName, policySchema, policyTable)
		d.SetId("")
		return nil
	case err != nil:
		return fmt.Errorf("Error reading policy: %w", err)
	}

	d.Set(policyNameAttr, policyName)
	d.Set(policySchemaAttr, policySchema)
	d.Set(policyTableAttr, policyTable)
	d.Set(policyToAttr, policyTo)
	d.Set(policyUsingAttr, policyUsing[1:len(policyUsing)-1])

	return nil
}

func resourcePostgreSQLPolicyUpdate(db *DBConnection, d *schema.ResourceData) error {
	policyName := d.Get(policyNameAttr).(string)
	policySchema := d.Get(policySchemaAttr).(string)
	policyTable := d.Get(policyTableAttr).(string)
	policyToRaw := d.Get(policyToAttr).([]interface{})
	policyUsing := d.Get(policyUsingAttr).(string)

	policyTo := make([]string, len(policyToRaw))
	for i := range policyToRaw {
		policyTo[i] = policyToRaw[i].(string)
	}

	txn, err := startTransaction(db.client, db.client.databaseName)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	if d.HasChange(policyNameAttr) {
		policyNameOld, _ := d.GetChange(policyNameAttr)

		b := bytes.NewBufferString("ALTER POLICY ")
		fmt.Fprint(b,
			pq.QuoteIdentifier(policyNameOld.(string)),
			" ON ",
			pq.QuoteIdentifier(policySchema), ".", pq.QuoteIdentifier(policyTable),
			" RENAME TO ",
			pq.QuoteIdentifier(policyName),
		)
		if _, err := txn.Exec(b.String()); err != nil {
			return err
		}
	}

	if d.HasChangeExcept(policyNameAttr) {
		b := bytes.NewBufferString("ALTER POLICY ")
		fmt.Fprint(b,
			pq.QuoteIdentifier(policyName),
			" ON ",
			pq.QuoteIdentifier(policySchema), ".", pq.QuoteIdentifier(policyTable),
			" TO ",
			strings.Join(policyTo, ", "), // TODO: quote policyTo
			" USING (",
			policyUsing,
			")",
		)
		if _, err := txn.Exec(b.String()); err != nil {
			return err
		}
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error updating Policy: %w", err)
	}

	d.SetId(generatePolicyID(d))

	return resourcePostgreSQLPolicyRead(db, d)
}

func resourcePostgreSQLPolicyDelete(db *DBConnection, d *schema.ResourceData) error {
	policyName := d.Get(policyNameAttr).(string)
	policySchema := d.Get(policySchemaAttr).(string)
	policyTable := d.Get(policyTableAttr).(string)

	txn, err := startTransaction(db.client, db.client.databaseName)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	b := bytes.NewBufferString("DROP POLICY IF EXISTS ")
	fmt.Fprint(b, pq.QuoteIdentifier(policyName), " ON ", pq.QuoteIdentifier(policySchema), ".", pq.QuoteIdentifier(policyTable))

	if _, err := txn.Exec(b.String()); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error deleting Policy: %w", err)
	}

	d.SetId("")

	return nil
}

func resourcePostgreSQLPolicyExists(db *DBConnection, d *schema.ResourceData) (bool, error) {
	var policySchema string
	var policyTable string
	var policyName string
	policySchema, policyTable, policyName = getInfoFromID(d.Id())

	err := db.QueryRow(
		"SELECT policyname FROM pg_policies WHERE policyname = $1 AND schemaname = $2 AND tablename = $3",
		policyName, policySchema, policyTable,
	).Scan(&policyName)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func generatePolicyID(d *schema.ResourceData) string {
	return strings.Join([]string{
		d.Get(policySchemaAttr).(string),
		d.Get(policyTableAttr).(string),
		d.Get(policyNameAttr).(string),
	}, ".")
}

func getInfoFromID(ID string) (string, string, string) {
	splitted := strings.Split(ID, ".")
	return splitted[0], splitted[1], splitted[2]
}
