const { executeQuery } = require("../config/database")

// Evaluador principal de políticas ABAC
async function evaluatePolicy(context, resource, action, userRoles) {
  try {
    // 1. Evaluación basada en roles (RBAC tradicional)
    const rbacDecision = evaluateRBAC(userRoles, resource, action)

    // 2. Obtener políticas específicas para el recurso
    const policies = await executeQuery(
      "SELECT * FROM access_policies WHERE resource = ? OR resource = '*' ORDER BY priority DESC",
      [resource],
    )

    // 3. Evaluar políticas ABAC
    const abacDecisions = []
    for (const policy of policies) {
      const policyDecision = evaluatePolicyRule(policy, context, action)
      abacDecisions.push(policyDecision)
    }

    // 4. Combinar decisiones (RBAC + ABAC)
    const finalDecision = combineDecisions(rbacDecision, abacDecisions)

    return finalDecision
  } catch (error) {
    console.error("Error evaluando política:", error)
    return {
      permit: false,
      decision: "ERROR",
      reasons: ["Error interno evaluando política"],
    }
  }
}

// Evaluación RBAC tradicional
function evaluateRBAC(userRoles, resource, action) {
  let hasPermission = false
  const reasons = []

  for (const role of userRoles) {
    const permissions = JSON.parse(role.permissions)

    if (permissions[resource] && permissions[resource].includes(action)) {
      hasPermission = true
      reasons.push(`Rol '${role.name}' permite '${action}' en '${resource}'`)
      break
    }
  }

  if (!hasPermission) {
    reasons.push(`Ningún rol permite '${action}' en '${resource}'`)
  }

  return {
    type: "RBAC",
    permit: hasPermission,
    reasons: reasons,
  }
}

// Evaluación de regla de política específica
function evaluatePolicyRule(policy, context, action) {
  try {
    const conditions = JSON.parse(policy.conditions)
    const allowedActions = JSON.parse(policy.actions)

    // Verificar si la acción está permitida en la política
    if (!allowedActions.includes(action) && !allowedActions.includes("*")) {
      return {
        type: "ABAC",
        policyId: policy.id,
        policyName: policy.name,
        permit: false,
        reasons: [`Política '${policy.name}' no permite la acción '${action}'`],
      }
    }

    // Evaluar condiciones
    const conditionResults = evaluateConditions(conditions, context)

    const permit = policy.effect === "ALLOW" ? conditionResults.allMet : !conditionResults.allMet

    return {
      type: "ABAC",
      policyId: policy.id,
      policyName: policy.name,
      permit: permit,
      reasons: conditionResults.reasons,
      effect: policy.effect,
    }
  } catch (error) {
    return {
      type: "ABAC",
      policyId: policy.id,
      policyName: policy.name,
      permit: false,
      reasons: [`Error evaluando política '${policy.name}': ${error.message}`],
    }
  }
}

// Evaluador de condiciones
function evaluateConditions(conditions, context) {
  const results = []
  let allMet = true

  for (const [key, condition] of Object.entries(conditions)) {
    const result = evaluateCondition(key, condition, context)
    results.push(result.reason)

    if (!result.met) {
      allMet = false
    }
  }

  return {
    allMet: allMet,
    reasons: results,
  }
}

// Evaluador de condición individual
function evaluateCondition(key, condition, context) {
  try {
    const { operator, value, path } = condition

    // Obtener valor del contexto usando el path
    const contextValue = getValueFromPath(context, path || key)

    switch (operator) {
      case "equals":
        return {
          met: contextValue === value,
          reason: `${key}: ${contextValue} ${contextValue === value ? "==" : "!="} ${value}`,
        }

      case "not_equals":
        return {
          met: contextValue !== value,
          reason: `${key}: ${contextValue} ${contextValue !== value ? "!=" : "=="} ${value}`,
        }

      case "in":
        const inResult = Array.isArray(value) && value.includes(contextValue)
        return {
          met: inResult,
          reason: `${key}: ${contextValue} ${inResult ? "in" : "not in"} [${value.join(", ")}]`,
        }

      case "not_in":
        const notInResult = Array.isArray(value) && !value.includes(contextValue)
        return {
          met: notInResult,
          reason: `${key}: ${contextValue} ${notInResult ? "not in" : "in"} [${value.join(", ")}]`,
        }

      case "greater_than":
        const gtResult = Number(contextValue) > Number(value)
        return {
          met: gtResult,
          reason: `${key}: ${contextValue} ${gtResult ? ">" : "<="} ${value}`,
        }

      case "less_than":
        const ltResult = Number(contextValue) < Number(value)
        return {
          met: ltResult,
          reason: `${key}: ${contextValue} ${ltResult ? "<" : ">="} ${value}`,
        }

      case "between":
        const [min, max] = value
        const betweenResult = Number(contextValue) >= Number(min) && Number(contextValue) <= Number(max)
        return {
          met: betweenResult,
          reason: `${key}: ${contextValue} ${betweenResult ? "between" : "not between"} ${min}-${max}`,
        }

      case "regex":
        const regexResult = new RegExp(value).test(String(contextValue))
        return {
          met: regexResult,
          reason: `${key}: ${contextValue} ${regexResult ? "matches" : "doesn't match"} /${value}/`,
        }

      case "time_between":
        const currentHour = new Date().getHours()
        const [startHour, endHour] = value
        const timeResult = currentHour >= startHour && currentHour <= endHour
        return {
          met: timeResult,
          reason: `time: ${currentHour}h ${timeResult ? "between" : "not between"} ${startHour}h-${endHour}h`,
        }

      default:
        return {
          met: false,
          reason: `${key}: operador desconocido '${operator}'`,
        }
    }
  } catch (error) {
    return {
      met: false,
      reason: `${key}: error evaluando condición - ${error.message}`,
    }
  }
}

// Obtener valor del contexto usando path notation
function getValueFromPath(obj, path) {
  return path.split(".").reduce((current, key) => {
    return current && current[key] !== undefined ? current[key] : null
  }, obj)
}

// Combinar decisiones RBAC y ABAC
function combineDecisions(rbacDecision, abacDecisions) {
  const allReasons = [rbacDecision.reasons, ...abacDecisions.map((d) => d.reasons)].flat()

  // Si no hay políticas ABAC, usar solo RBAC
  if (abacDecisions.length === 0) {
    return {
      permit: rbacDecision.permit,
      decision: rbacDecision.permit ? "PERMIT" : "DENY",
      reasons: allReasons,
      evaluation: {
        rbac: rbacDecision,
        abac: [],
      },
    }
  }

  // Evaluar políticas ABAC
  let finalPermit = rbacDecision.permit

  // Buscar políticas DENY explícitas (tienen prioridad)
  const denyPolicies = abacDecisions.filter((d) => d.effect === "DENY" && d.permit)
  if (denyPolicies.length > 0) {
    finalPermit = false
  }

  // Si RBAC niega pero hay políticas ALLOW explícitas
  const allowPolicies = abacDecisions.filter((d) => d.effect === "ALLOW" && d.permit)
  if (!rbacDecision.permit && allowPolicies.length > 0) {
    finalPermit = true
  }

  return {
    permit: finalPermit,
    decision: finalPermit ? "PERMIT" : "DENY",
    reasons: allReasons,
    evaluation: {
      rbac: rbacDecision,
      abac: abacDecisions,
    },
  }
}

// Validar estructura de política
function validatePolicy(policy) {
  const errors = []

  if (!policy.name || policy.name.trim().length === 0) {
    errors.push("Nombre de política es requerido")
  }

  if (!policy.resource || policy.resource.trim().length === 0) {
    errors.push("Recurso es requerido")
  }

  if (!policy.effect || !["ALLOW", "DENY"].includes(policy.effect)) {
    errors.push("Efecto debe ser 'ALLOW' o 'DENY'")
  }

  if (!policy.actions || !Array.isArray(policy.actions) || policy.actions.length === 0) {
    errors.push("Acciones deben ser un array no vacío")
  }

  if (!policy.conditions || typeof policy.conditions !== "object") {
    errors.push("Condiciones deben ser un objeto")
  }

  // Validar estructura de condiciones
  if (policy.conditions && typeof policy.conditions === "object") {
    for (const [key, condition] of Object.entries(policy.conditions)) {
      if (!condition.operator) {
        errors.push(`Condición '${key}' requiere operador`)
      }

      if (condition.value === undefined) {
        errors.push(`Condición '${key}' requiere valor`)
      }
    }
  }

  return {
    isValid: errors.length === 0,
    errors: errors,
  }
}

// Crear política predefinida
function createPolicy(name, resource, actions, conditions, effect = "ALLOW", priority = 0) {
  return {
    name,
    resource,
    actions,
    conditions,
    effect,
    priority,
  }
}

module.exports = {
  evaluatePolicy,
  evaluateRBAC,
  evaluatePolicyRule,
  evaluateConditions,
  evaluateCondition,
  combineDecisions,
  validatePolicy,
  createPolicy,
}
