from django.db import models

class ApplicationResource(models.Model):
    name = models.CharField(max_length=100)
    url = models.URLField()

    assigned_policy = models.ForeignKey(
        'policy.Policy',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    criticality_level = models.IntegerField(default=1)

    def __str__(self):
        return f"{self.name} (Criticality: {self.criticality_level})"
