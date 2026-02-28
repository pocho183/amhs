package it.amhs.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import it.amhs.domain.AMHSDeliveryReport;
import it.amhs.domain.AMHSMessage;

@Repository
public interface AMHSDeliveryReportRepository extends JpaRepository<AMHSDeliveryReport, Long> {

    List<AMHSDeliveryReport> findByMessage(AMHSMessage message);
}
