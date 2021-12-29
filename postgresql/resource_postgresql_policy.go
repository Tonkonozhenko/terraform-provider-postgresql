package postgresql

import (
	"database/sql"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lib/pq"
	"log"
	"strings"
)

const (
	policyNameAttr              = "name"
	policySchemaAttr            = "schema"
	policyTableAttr             = "table"
	policyToAttr                = "to"
	policyUsingAttr             = "using"
	policyPathmanPartitionsAttr = "pathman_partitions"
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
			policyPathmanPartitionsAttr: {
				Type:        schema.TypeBool,
				Required:    false,
				Default:     false,
				Description: "Enable policy propagation to pathman partitions",
			},
		},
	}
}

func resourcePostgreSQLPolicyCreate(db *DBConnection, d *schema.ResourceData) error {
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

	tablePartitions, err := tablePartitions(db, d)
	if err != nil {
		return err
	}

	for _, partition := range tablePartitions {
		q1 := fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", partition)

		if _, err := txn.Exec(q1); err != nil {
			return err
		}

		q2 := fmt.Sprintf(
			"CREATE POLICY %s ON %s TO %s USING (%s)",
			pq.QuoteIdentifier(policyName),
			partition,
			strings.Join(policyTo, ", "), // TODO: quote policyTo
			policyUsing,
		)
		if _, err := txn.Exec(q2); err != nil {
			return err
		}
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error creating Policy: %w", err)
	}

	d.SetId(generatePolicyID(d))

	return resourcePostgreSQLPolicyRead(db, d)
}

func tablePartitions(db *DBConnection, d *schema.ResourceData) ([]string, error) {
	policySchema := d.Get(policySchemaAttr).(string)
	policyTable := d.Get(policyTableAttr).(string)
	policyPathmanPartitions := d.Get(policyPathmanPartitionsAttr).(bool)

	var tablePartitions []string
	schemaAndTable := pq.QuoteIdentifier(policySchema) + "." + pq.QuoteIdentifier(policyTable)

	if policyPathmanPartitions {
		err := db.QueryRow(
			`SELECT array_agg(p.part) AS tables
FROM (
         SELECT $1 AS part
         UNION ALL
         SELECT partition AS part
         FROM pathman_partition_list ppl
         WHERE ppl.parent = $1::regclass
     ) p
         JOIN pg_class pc
              ON pc.oid = p.part::regclass
WHERE pc.relkind != 'f'`,
			schemaAndTable,
		).Scan(pq.Array(&tablePartitions))
		switch {
		case err != nil:
			return nil, fmt.Errorf("error reading partitions: %w", err)
		}
	} else {
		tablePartitions = append(tablePartitions, schemaAndTable)
	}
	return tablePartitions, nil
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
	//d.Set(policyUsingAttr, policyUsing[1:len(policyUsing)-1])

	return nil
}

func resourcePostgreSQLPolicyUpdate(db *DBConnection, d *schema.ResourceData) error {
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

	tablePartitions, err := tablePartitions(db, d)
	if err != nil {
		return err
	}

	for _, partition := range tablePartitions {
		if d.HasChange(policyNameAttr) {
			policyNameOld, _ := d.GetChange(policyNameAttr)

			q := fmt.Sprintf(
				"ALTER POLICY %s ON %s RENAME TO %s",
				pq.QuoteIdentifier(policyNameOld.(string)),
				partition,
				pq.QuoteIdentifier(policyName),
			)
			if _, err := txn.Exec(q); err != nil {
				return err
			}
		}

		if d.HasChangeExcept(policyNameAttr) {
			q := fmt.Sprintf(
				"ALTER POLICY %s ON %s TO %s USING (%s)",
				pq.QuoteIdentifier(policyName),
				partition,
				strings.Join(policyTo, ", "), // TODO: quote policyTo
				policyUsing,
			)
			if _, err := txn.Exec(q); err != nil {
				return err
			}
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

	txn, err := startTransaction(db.client, db.client.databaseName)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	tablePartitions, err := tablePartitions(db, d)
	if err != nil {
		return err
	}

	for _, partition := range tablePartitions {
		q := fmt.Sprintf(
			"DROP POLICY IF EXISTS %s ON %s",
			pq.QuoteIdentifier(policyName),
			partition,
		)

		if _, err := txn.Exec(q); err != nil {
			return err
		}
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
